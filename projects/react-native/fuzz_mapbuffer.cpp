/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Fuzz target: MapBuffer binary deserializer
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * ATTACK SURFACE & DATA FLOW
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * MapBuffer is React Native's compact binary key-value format used to
 * transfer component props across the C++ ↔ Java/ObjC bridge.  In the
 * Fabric (new) architecture the primary data flow that reaches this code
 * with attacker-influenced bytes is:
 *
 *   1. Server-Driven React Native (SDRN / React Server Components):
 *      Server → HTTP response (JSON/binary payload)
 *        → React Native JS runtime parses server tree
 *        → Shadow tree props serialized to MapBuffer in C++ via JSI
 *        → MapBuffer bytes passed to JNI ReadableMapBuffer on Android
 *            or equivalent on iOS
 *        → MapBuffer(std::vector<uint8_t>) ← OUR ENTRY POINT
 *        → accessors (getInt, getString, …) ← OUR ACCESSORS
 *
 *   2. Supply-chain / bundle compromise:
 *      A tampered JS bundle makes component prop objects that become
 *      MapBuffer bytes in C++; any consumer of the MapBuffer then calls
 *      accessors that perform binary-search and offset arithmetic on those
 *      bytes.
 *
 *   3. Hot-reload in development:
 *      Dev server sends updated bundle over WebSocket; the parser path is
 *      identical to (2) but faster to exploit in dev scenarios.
 *
 *   Note: In vanilla production builds with static, signed bundles the
 *   attack surface is indirect (requires bundle supply-chain compromise).
 *   SDRN deployments (used by Meta internally in Facebook/Instagram apps)
 *   present the highest-priority direct attack surface.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * WIRE FORMAT
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *   ┌──────────┬──────────┬──────────────────┐  Header — 8 bytes
 *   │alignment │  count   │   bufferSize      │
 *   │ uint16_t │ uint16_t │    uint32_t       │
 *   └──────────┴──────────┴──────────────────┘
 *   ┌──────┬───────┬──────────────────────────┐  Bucket — 12 bytes × count
 *   │ key  │ type  │  data (primitive/offset)  │
 *   │ u16  │  u16  │       uint64_t            │
 *   └──────┴───────┴──────────────────────────┘
 *   [ dynamic data: strings, nested MapBuffers, lists … ]
 *
 *   DataType enum: Boolean=0, Int=1, Double=2, String=3, Map=4, Long=5
 *   (static_assert'd to 12 bytes for Bucket, 8 bytes for Header)
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * BUG CLASSES TARGETED
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  A. getKeyBucket() heap-buffer-overflow (ASan):
 *     count_ is an attacker-controlled uint16_t (max 65535).  The binary
 *     search walks bytes_.data() + 8 + 12 * mid; for count_=65535 and a
 *     tiny buffer, mid≈32767 → read at byte 393212 of a ~20-byte heap
 *     allocation.
 *
 *  B. Dynamic-area offset OOB (ASan):
 *     Offset values stored in bucket data fields index into the dynamic
 *     area; a crafted offset can extend past the allocation end.
 *     Affects getString, getMapBuffer, and getMapBufferList accessors.
 *
 *  C. Signed-integer overflow in getMapBufferList() (UBSan):
 *     curLen (int32_t) += mapBufferLength (int32_t); multiple large entries
 *     can overflow into negative, breaking the while-loop termination.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * STRATEGY
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * The MapBuffer constructor hard-aborts when header->bufferSize != bytes_.size().
 * We patch that field to equal the actual input size before every construction,
 * leaving count_ and all bucket/dynamic data fully attacker-controlled.
 *
 * Three test phases:
 *
 *   Phase 1 — Flat fuzzing:
 *     Directly construct a MapBuffer from fuzz bytes and exercise every
 *     strongly-typed accessor.  count_ is free to be 0–65535.
 *
 *   Phase 2 — Nested Map via MapBufferBuilder:
 *     Wrap a fuzz-derived inner MapBuffer inside a structurally valid outer
 *     MapBuffer using MapBufferBuilder::putMapBuffer().  Exercise
 *     getMapBuffer() to deserialize the inner buffer, then exercise every
 *     accessor on the resulting inner MapBuffer.  This tests the two-level
 *     deserialisation path without triggering abort() in either constructor.
 *
 *   Phase 3 — Nested List via MapBufferBuilder:
 *     Store the fuzz-derived inner MapBuffer as a single-element list via
 *     MapBufferBuilder::putMapBufferList().  Exercise getMapBufferList() to
 *     deserialize, then accessor calls on each returned element.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <react/renderer/mapbuffer/MapBuffer.h>
#include <react/renderer/mapbuffer/MapBufferBuilder.h>

namespace {

using MB  = facebook::react::MapBuffer;
using MBB = facebook::react::MapBufferBuilder;

// Header is 8 bytes: alignment(2) + count(2) + bufferSize(4).
constexpr size_t kHeaderSize = sizeof(MB::Header);

// Probe keys that span the entire Key range (uint16_t, 0–0xFFFF).
// libFuzzer can mutate bucket key fields to match any of these, exercising
// both the "key found" and "key not found" branches of getKeyBucket().
constexpr MB::Key kProbeKeys[] = {
    0x0000, 0x0001, 0x0002, 0x0003, 0x000A, 0x0064,
    0x0100, 0x0FFF, 0x1000, 0x7FFF, 0x7FFE, 0xFFFE, 0xFFFF,
};

// Patches Header::bufferSize at byte-offset 4 to equal `actualSize`.
// This prevents the hard abort() in MapBuffer(vector<uint8_t>) while
// leaving all other bytes—including count_, every bucket, and the entire
// dynamic data area—under libFuzzer's control.
void patchBufferSize(std::vector<uint8_t>& buf) {
  const uint32_t actualSize = static_cast<uint32_t>(buf.size());
  std::memcpy(
      buf.data() + offsetof(MB::Header, bufferSize),
      &actualSize,
      sizeof(actualSize));
}

// Call every non-getMapBuffer accessor on `mb` for each probe key.
// Exercises getKeyBucket() binary search, all typed-value accessors
// (getInt/getLong/getBool/getDouble), and the dynamic-area string path.
void exerciseAccessors(const MB& mb) {
  (void)mb.count();
  (void)mb.size();
  for (auto key : kProbeKeys) {
    mb.getInt(key);
    mb.getLong(key);
    mb.getBool(key);
    mb.getDouble(key);
    mb.getString(key);
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < kHeaderSize) {
    return 0;
  }

  // Keep a patched copy of the fuzz bytes for reuse across phases.
  // vector copy is safe here; MapBuffer(vector&&) moves, not copies.
  std::vector<uint8_t> patchedBuf(data, data + size);
  patchBufferSize(patchedBuf);

  // ───────────────────────────────────────────────────────────────────────
  // Phase 1: Flat MapBuffer fuzzing
  // ───────────────────────────────────────────────────────────────────────
  // count_ = patchedBuf[2..3] (uint16_t, attacker-controlled, 0–65535).
  // Large count_ means getKeyBucket() reads buckets far past the buffer.
  {
    auto buf1 = patchedBuf; // copy vector before moving
    MB mb(std::move(buf1));
    exerciseAccessors(mb);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Phase 2: Nested Map — MapBufferBuilder::putMapBuffer
  // ───────────────────────────────────────────────────────────────────────
  // Outer structure (built via MapBufferBuilder, structurally correct):
  //   Header: count=1, bufferSize=24+size
  //   Bucket: key=0x0001, type=Map=4, data=0 (dynamic-area offset)
  //   Dynamic:  [4B length=size] [fuzz bytes with patched bufferSize]
  //
  // getMapBuffer(1) reads [length][fuzz bytes], constructs inner MapBuffer.
  // The inner constructor sees bufferSize==size (we patched it), so it
  // succeeds.  The inner MapBuffer then has attacker-controlled count_ and
  // all bucket/dynamic data → exerciseAccessors() can OOB inside it.
  //
  // putMapBuffer() only calls map.size() and map.data()—both are safe read-
  // only operations that never traverse bucket fields.
  if (size >= kHeaderSize) {
    auto buf2 = patchedBuf; // copy before moving
    MB fuzzInner(std::move(buf2));

    MBB outerBuilder(/*initialSize=*/1);
    outerBuilder.putMapBuffer(/*key=*/0x0001, fuzzInner);
    MB outer = outerBuilder.build();

    // Exercise outer first (it is well-formed, so this is a robustness
    // sanity check and verifies the builder output is consistent).
    (void)outer.count();
    (void)outer.size();

    // Deserialize the nested buffer.  Inner has attacker-controlled bytes.
    MB inner = outer.getMapBuffer(/*key=*/0x0001);
    exerciseAccessors(inner);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Phase 3: Nested List — MapBufferBuilder::putMapBufferList
  // ───────────────────────────────────────────────────────────────────────
  // putMapBufferList stores:
  //   [4B totalListSize] [4B entry0Size] [entry0 bytes] ...
  //
  // getMapBufferList() iterates with:
  //   while (curLen < mapBufferListLength) {
  //     int32_t mapBufferLength = bytes_[offset + curLen];  // attacker ctrl
  //     curLen += sizeof(uint32_t);
  //     ... vector<uint8_t>(mapBufferLength) ...
  //     curLen += mapBufferLength;                           // UBSan target
  //   }
  //
  // A crafted mapBufferLength in the fuzz inner buffer's count/data fields
  // could eventually cause signed-integer overflow in the curLen accumulation
  // across multiple elements (UBSan).  With a single valid element this path
  // is safe but exercises the list-deserialization code that is otherwise
  // unreachable from Phase 1 or Phase 2.
  if (size >= kHeaderSize) {
    auto buf3 = patchedBuf; // copy before moving
    MB fuzzInner3(std::move(buf3));

    std::vector<MB> listVec;
    listVec.push_back(std::move(fuzzInner3));

    MBB listBuilder(/*initialSize=*/1);
    listBuilder.putMapBufferList(/*key=*/0x0002, listVec);
    MB outerList = listBuilder.build();

    (void)outerList.count();
    (void)outerList.size();

    // Deserialize the list; each element is an inner MapBuffer with
    // attacker-controlled count_ and dynamic data.
    auto elements = outerList.getMapBufferList(/*key=*/0x0002);
    for (const auto& elem : elements) {
      exerciseAccessors(elem);
    }
  }

  return 0;
}

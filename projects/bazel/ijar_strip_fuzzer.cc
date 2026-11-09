// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// OSS-Fuzz fuzz target for Bazel's ijar class-file parser (third_party/ijar).
//
// ijar runs at *build time* (compilation avoidance) over every dependency
// `.class` inside a `.jar`, BEFORE any dependency code is executed, on the
// developer/CI build host. The real entry point is:
//
//   JarStripperProcessor::Process (ijar.cc:179)
//     u1 *buf = malloc(size);              // ijar.cc:190 — output sized to INPUT
//     StripClass(buf, data, size);         // ijar.cc:192
//
// This target mirrors that exactly: the fuzz input is the raw `.class` byte
// stream, the output buffer is sized to the input length, and StripClass()
// parses and re-emits it. Crafted attributes (e.g. a Record attribute whose
// u4 attribute_length is decoupled from its u2 component count) overflow a
// `new u1[attribute_length_]` buffer in RecordAttribute::Write (classfile.cc).
//
// Build (OSS-Fuzz): see projects/bazel/build.sh.
// Build (local, no clang): see verify_fuzzer_local.sh (StandaloneFuzzTargetMain).

#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "third_party/ijar/common.h"

namespace devtools_ijar {
// Defined in ijar.cc, which we deliberately exclude (it carries main()).
bool verbose = false;
bool StripClass(u1 *&classdata_out, const u1 *classdata_in, size_t in_length);
}  // namespace devtools_ijar

using namespace devtools_ijar;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Skip inputs too short to carry even a class-file header (magic[4] +
  // minor[2] + major[2] + constant_pool_count[2] = 10 bytes). ijar's ReadClass
  // does NO length validation, so sub-header inputs trip a shallow get_u4be
  // out-of-bounds READ (classfile.cc:1764) that would otherwise mask the deeper
  // write-side Record/attribute overflow this target is meant to exercise. The
  // shallow read OOB is a real, separately-reported ijar defect; guarding it
  // here keeps the target runnable for continuous fuzzing (OSS-Fuzz idiom).
  if (size < 10) return 0;

  // Copy the input into a tightly-sized heap allocation so ASAN bounds any
  // out-of-bounds *reads* of the class stream as well as output overflows.
  u1 *in = static_cast<u1 *>(malloc(size));
  if (in == nullptr) return 0;
  memcpy(in, data, size);

  // Output buffer sized to the input length, exactly like ijar.cc:190.
  u1 *buf = static_cast<u1 *>(malloc(size));
  if (buf == nullptr) {
    free(in);
    return 0;
  }

  u1 *out = buf;
  StripClass(out, in, size);  // ijar.cc:192 — the vulnerable re-emit path

  free(buf);
  free(in);
  return 0;
}

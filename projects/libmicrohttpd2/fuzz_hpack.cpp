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
//
////////////////////////////////////////////////////////////////////////////////
//
// Fuzzer for the HTTP/2 HPACK header-compression codec
// (src/mhd2/h2/hpack/mhd_hpack_codec.c and h2_huffman_codec.c).
//
// Threat model: in HTTP/2 the HEADERS / CONTINUATION frame payload (the
// "header block fragment") is attacker controlled and is passed to
// mhd_hpack_dec_data() representation by representation, exactly as done in
// h2_req_fields.c.  The decoder maintains a dynamic table that is mutated by
// the attacker (literal-with-indexing, dynamic table size updates), so the
// whole byte stream of a header block is fed through ONE decoder context.
//
// Input layout (FuzzedDataProvider):
//   1. output buffer size for decoded fields (server-side buffer, 2..8192)
//   2. maximum allowed decoder dynamic table size (server SETTINGS value)
//   3. encoder dynamic table size + encoding policy seed (round-trip only)
//   4. remaining bytes: the HPACK header block (attacker data)
//
// Every successfully decoded regular field is also re-encoded with the MHD
// HPACK encoder and decoded again by an independent decoder, which exercises
// the encoder, Huffman encoding and the dynamic table of both sides.  On any
// unexpected result the harness returns so that fuzzing continues.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "mhd_sys_options.h"
#include "mhd_buffer.h"
#include "mhd_lib_init.h"
#include "h2/hpack/mhd_hpack_codec.h"
#include "h2/hpack/mhd_hpack_dec_types.h"
#include "h2/hpack/mhd_hpack_enc_types.h"

namespace {

constexpr size_t kMaxOutBuff = 8192;

// Re-encode a decoded field and decode it with a peer decoder.  Returns early
// on any unexpected result.
void RoundTrip(struct mhd_HpackEncContext *enc,
               struct mhd_HpackDecContext *peer,
               enum mhd_HpackEncPolicy pol,
               const char *name, size_t name_len,
               const char *val, size_t val_len) {
  struct mhd_BufferConst n;
  struct mhd_BufferConst v;
  n.size = name_len;
  n.data = name;
  v.size = val_len;
  v.data = val;

  // Generous output buffer: the encoder may emit a dynamic table size update
  // plus a literal.  Huffman never expands by more than 30/8 per byte.
  const size_t enc_cap = 64 + (name_len + val_len) * 4;
  std::vector<uint8_t> enc_buf(enc_cap);
  size_t enc_len = 0;
  if (mhd_HPACK_ENC_RES_OK !=
      mhd_hpack_enc_field(enc, &n, &v, pol, enc_buf.size(), enc_buf.data(),
                          &enc_len))
    return;
  if (enc_len > enc_buf.size())
    return;

  std::vector<char> out(name_len + val_len + 2 + 16);
  size_t pos = 0;
  bool got_field = false;
  while (pos < enc_len) {
    size_t nl = 0, vl = 0, used = 0;
    enum mhd_HpackDecResult r =
        mhd_hpack_dec_data(peer, enc_len - pos, enc_buf.data() + pos,
                           out.size(), out.data(), &nl, &vl, &used);
    if (mhd_HPACK_DEC_RES_IS_ERR(r) || 0 == used)
      return;
    pos += used;
    if (mhd_HPACK_DEC_RES_NEW_FIELD == r) {
      if (got_field || pos != enc_len)
        return;
      if (nl != name_len || vl != val_len ||
          0 != memcmp(out.data(), name, name_len) ||
          0 != memcmp(out.data() + nl + 1, val, val_len))
        return;
      got_field = true;
    }
  }
}

// False if global library initialisation failed; every input is then skipped.
bool g_lib_init_ok = false;

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  // Global library initialisation, as done by MHD on daemon start.  Among
  // other things this builds the Huffman decoding tables
  // (mhd_h2_huffman_init()), without which every Huffman string is rejected.
  g_lib_init_ok = mhd_lib_init_global_if_needed();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!g_lib_init_ok)
    return 0;

  FuzzedDataProvider fdp(data, size);

  const size_t out_size = fdp.ConsumeIntegralInRange<size_t>(2, kMaxOutBuff);
  static const size_t kAllowedDyn[] = {4096, 0, 64, 256, 1024, 16384, 65536};
  const size_t allowed_dyn = fdp.PickValueInArray(kAllowedDyn);
  static const size_t kEncDyn[] = {4096, 0, 128, 1024};
  const size_t enc_dyn = fdp.PickValueInArray(kEncDyn);
  const uint8_t pol_seed = fdp.ConsumeIntegral<uint8_t>();

  std::vector<uint8_t> block = fdp.ConsumeRemainingBytes<uint8_t>();
  if (block.empty())
    return 0;

  struct mhd_HpackDecContext dec;
  struct mhd_HpackEncContext enc;
  struct mhd_HpackDecContext peer;
  if (!mhd_hpack_dec_init(&dec))
    return 0;
  if (!mhd_hpack_enc_init(&enc)) {
    mhd_hpack_dec_deinit(&dec);
    return 0;
  }
  if (!mhd_hpack_dec_init(&peer)) {
    mhd_hpack_enc_deinit(&enc);
    mhd_hpack_dec_deinit(&dec);
    return 0;
  }
  if (4096 != allowed_dyn)
    mhd_hpack_dec_set_allowed_dyn_size(&dec, allowed_dyn);
  if (4096 != enc_dyn) {
    // The peer decoder keeps the default (4096) limit, so any smaller encoder
    // table is always acceptable to it.
    mhd_hpack_enc_set_dyn_size(&enc, enc_dyn);
    (void)mhd_hpack_enc_dyn_resize(&enc);
  }

  // Exactly-sized heap buffer so that ASan catches any out-of-bounds write.
  char *out = static_cast<char *>(malloc(out_size));
  if (out == nullptr) {
    mhd_hpack_dec_deinit(&peer);
    mhd_hpack_enc_deinit(&enc);
    mhd_hpack_dec_deinit(&dec);
    return 0;
  }

  size_t pos = 0;
  unsigned int field_no = 0;
  while (pos < block.size()) {
    size_t name_len = 0, val_len = 0, used = 0;
    enum mhd_HpackDecResult r =
        mhd_hpack_dec_data(&dec, block.size() - pos, block.data() + pos,
                           out_size, out, &name_len, &val_len, &used);
    if (mhd_HPACK_DEC_RES_IS_ERR(r))
      break;  // Connection error in a real server (COMPRESSION_ERROR).
    if (used == 0 || used > block.size() - pos)
      break;  // No progress within the input: stop, avoiding an endless loop.
    pos += used;
    if (mhd_HPACK_DEC_RES_NEW_FIELD != r)
      continue;

    // API contract: "name\0value\0" written into out_buff.
    if (name_len + val_len + 2 > out_size)
      break;
    if (out[name_len] != '\0' || out[name_len + 1 + val_len] != '\0')
      break;

    const char *name = out;
    const char *val = out + name_len + 1;
    if (name_len != 0 && name[0] != ':') {
      const enum mhd_HpackEncPolicy pol = static_cast<enum mhd_HpackEncPolicy>(
          (pol_seed + field_no) %
          (mhd_HPACK_ENC_POL_NEVER_W_NAME_LIT_NO_HUFFMAN + 1));
      RoundTrip(&enc, &peer, pol, name, name_len, val, val_len);
    }
    ++field_no;
  }

  free(out);
  mhd_hpack_dec_deinit(&peer);
  mhd_hpack_enc_deinit(&enc);
  mhd_hpack_dec_deinit(&dec);
  return 0;
}

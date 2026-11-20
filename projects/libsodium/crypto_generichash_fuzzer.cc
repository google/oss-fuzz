// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sodium.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (sodium_init() == -1) {
    return 0;
  }

  // We need some data for outlen, keylen, and the message itself
  if (size < 2) {
    return 0;
  }

  size_t outlen = (data[0] % (crypto_generichash_BYTES_MAX - crypto_generichash_BYTES_MIN + 1)) + crypto_generichash_BYTES_MIN;
  size_t keylen = (data[1] % (crypto_generichash_KEYBYTES_MAX - crypto_generichash_KEYBYTES_MIN + 1));
  
  if (keylen > 0 && size < 2 + keylen) {
      keylen = 0;
  }

  const uint8_t *key = keylen > 0 ? data + 2 : NULL;
  const uint8_t *msg = data + 2 + keylen;
  size_t msglen = size - (2 + keylen);

  unsigned char out[crypto_generichash_BYTES_MAX];

  // Single-part API
  crypto_generichash(out, outlen, msg, msglen, key, keylen);

  // Multi-part API
  crypto_generichash_state state;
  if (crypto_generichash_init(&state, key, keylen, outlen) == 0) {
      // Split msg into two parts if possible
      if (msglen > 0) {
          size_t part1 = msglen / 2;
          crypto_generichash_update(&state, msg, part1);
          crypto_generichash_update(&state, msg + part1, msglen - part1);
      } else {
          crypto_generichash_update(&state, msg, 0);
      }
      crypto_generichash_final(&state, out, outlen);
  }

  return 0;
}

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

  if (size < crypto_kdf_KEYBYTES + 8 + 8) {
    return 0;
  }

  const uint8_t *key = data;
  uint64_t subkey_id;
  memcpy(&subkey_id, data + crypto_kdf_KEYBYTES, 8);
  
  char ctx[crypto_kdf_CONTEXTBYTES];
  memcpy(ctx, data + crypto_kdf_KEYBYTES + 8, crypto_kdf_CONTEXTBYTES > (size - (crypto_kdf_KEYBYTES + 8)) ? (size - (crypto_kdf_KEYBYTES + 8)) : crypto_kdf_CONTEXTBYTES);
  if (crypto_kdf_CONTEXTBYTES > (size - (crypto_kdf_KEYBYTES + 8))) {
      memset(ctx + (size - (crypto_kdf_KEYBYTES + 8)), 0, crypto_kdf_CONTEXTBYTES - (size - (crypto_kdf_KEYBYTES + 8)));
  }

  // subkey length can be between crypto_kdf_BYTES_MIN and crypto_kdf_BYTES_MAX
  size_t subkey_len = crypto_kdf_BYTES_MIN + (data[size-1] % (crypto_kdf_BYTES_MAX - crypto_kdf_BYTES_MIN + 1));
  
  unsigned char *subkey = (unsigned char *)malloc(subkey_len);
  
  crypto_kdf_derive_from_key(subkey, subkey_len, subkey_id, ctx, key);

  free(subkey);

  return 0;
}

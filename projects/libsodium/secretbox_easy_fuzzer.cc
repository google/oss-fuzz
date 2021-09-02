// Copyright 2018 Google Inc.
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

#include <assert.h>
#include <stdlib.h>
#include <sodium.h>

#include "fake_random.h"

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  int initialized = sodium_init();
  assert(initialized >= 0);

  setup_fake_random(data, size);

  unsigned char key[crypto_secretbox_KEYBYTES];
  unsigned char nonce[crypto_secretbox_NONCEBYTES];

  // these use a deterministic generator
  crypto_secretbox_keygen(key);
  randombytes_buf(nonce, sizeof nonce);

  size_t ciphertext_len = crypto_secretbox_MACBYTES + size;
  unsigned char *ciphertext = (unsigned char *) malloc(ciphertext_len);

  crypto_secretbox_easy(ciphertext, data, size, nonce, key);

  unsigned char *decrypted = (unsigned char *) malloc(size);
  int err = crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce, key);
  assert(err == 0);

  free((void *) ciphertext);
  free((void *) decrypted);

  return 0;
}

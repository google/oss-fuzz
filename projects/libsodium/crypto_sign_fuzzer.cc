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

#include <assert.h>
#include <stdlib.h>
#include <sodium.h>

#include "fake_random.h"

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  int initialized = sodium_init();
  assert(initialized >= 0);

  if (size < crypto_sign_SEEDBYTES) {
    return 0;
  }

  setup_fake_random(data, size);

  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];

  const unsigned char *seed = data;
  const unsigned char *msg = data + crypto_sign_SEEDBYTES;
  size_t msg_len = size - crypto_sign_SEEDBYTES;

  crypto_sign_seed_keypair(pk, sk, seed);

  unsigned char *sig = (unsigned char *) malloc(crypto_sign_BYTES);
  unsigned long long sig_len;
  int err = crypto_sign_detached(sig, &sig_len, msg, msg_len, sk);
  assert(err == 0);
  assert(sig_len == crypto_sign_BYTES);

  err = crypto_sign_verify_detached(sig, msg, msg_len, pk);
  assert(err == 0);

  // Test multi-part signature
  crypto_sign_state state;
  crypto_sign_init(&state);
  crypto_sign_update(&state, msg, msg_len / 2);
  crypto_sign_update(&state, msg + msg_len / 2, msg_len - msg_len / 2);
  unsigned char sig2[crypto_sign_BYTES];
  err = crypto_sign_final_create(&state, sig2, &sig_len, sk);
  assert(err == 0);

  // For verification, we need a new state or re-initialized state
  crypto_sign_init(&state);
  crypto_sign_update(&state, msg, msg_len / 2);
  crypto_sign_update(&state, msg + msg_len / 2, msg_len - msg_len / 2);
  err = crypto_sign_final_verify(&state, sig2, pk);
  assert(err == 0);

  free(sig);

  return 0;
}

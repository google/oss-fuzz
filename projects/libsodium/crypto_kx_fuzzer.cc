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

  if (size < crypto_kx_SEEDBYTES + crypto_kx_PUBLICKEYBYTES) {
    return 0;
  }

  unsigned char pk[crypto_kx_PUBLICKEYBYTES];
  unsigned char sk[crypto_kx_SECRETKEYBYTES];
  unsigned char seed[crypto_kx_SEEDBYTES];
  
  memcpy(seed, data, crypto_kx_SEEDBYTES);
  
  // Test keypair generation from seed
  crypto_kx_seed_keypair(pk, sk, seed);

  unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
  unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
  unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
  unsigned char server_sk[crypto_kx_SECRETKEYBYTES];
  
  // Use data to simulate other party's public key
  memcpy(server_pk, data + size - crypto_kx_PUBLICKEYBYTES, crypto_kx_PUBLICKEYBYTES);
  
  unsigned char rx[crypto_kx_SESSIONKEYBYTES];
  unsigned char tx[crypto_kx_SESSIONKEYBYTES];

  // Test client session keys
  crypto_kx_client_session_keys(rx, tx, pk, sk, server_pk);

  // Test server session keys
  // We'll use the same 'pk' and 'sk' as server keys now
  memcpy(client_pk, data + size - crypto_kx_PUBLICKEYBYTES, crypto_kx_PUBLICKEYBYTES);
  crypto_kx_server_session_keys(rx, tx, pk, sk, client_pk);

  return 0;
}

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
#include <stdint.h>
#include <string.h>
#include <sodium.h>

#include "fake_random.h"

typedef int (*aead_encrypt_fn)(unsigned char *cipher,
                               unsigned long long *cipher_len,
                               const unsigned char *message,
                               unsigned long long message_len,
                               const unsigned char *ad,
                               unsigned long long ad_len,
                               const unsigned char *nsec,
                               const unsigned char *npub,
                               const unsigned char *k);

typedef int (*aead_decrypt_fn)(unsigned char *message,
                               unsigned long long *message_len,
                               unsigned char *nsec,
                               const unsigned char *cipher,
                               unsigned long long cipher_len,
                               const unsigned char *ad,
                               unsigned long long ad_len,
                               const unsigned char *npub,
                               const unsigned char *k);

struct AEAD_Algorithm {
    aead_encrypt_fn encrypt;
    aead_decrypt_fn decrypt;
    size_t key_bytes;
    size_t npub_bytes;
    size_t a_bytes;
    int (*is_available)(void);
};

static int always_available(void) { return 1; }

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  if (sodium_init() == -1) {
    return 0;
  }

  if (size < 2) {
    return 0;
  }

  static AEAD_Algorithm algs[] = {
    {
      crypto_aead_chacha20poly1305_ietf_encrypt,
      crypto_aead_chacha20poly1305_ietf_decrypt,
      crypto_aead_chacha20poly1305_ietf_KEYBYTES,
      crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
      crypto_aead_chacha20poly1305_ietf_ABYTES,
      always_available
    },
    {
      crypto_aead_xchacha20poly1305_ietf_encrypt,
      crypto_aead_xchacha20poly1305_ietf_decrypt,
      crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
      crypto_aead_xchacha20poly1305_ietf_ABYTES,
      always_available
    },
    {
      crypto_aead_chacha20poly1305_encrypt,
      crypto_aead_chacha20poly1305_decrypt,
      crypto_aead_chacha20poly1305_KEYBYTES,
      crypto_aead_chacha20poly1305_NPUBBYTES,
      crypto_aead_chacha20poly1305_ABYTES,
      always_available
    },
#ifdef crypto_aead_aegis128l_KEYBYTES
    {
      crypto_aead_aegis128l_encrypt,
      crypto_aead_aegis128l_decrypt,
      crypto_aead_aegis128l_KEYBYTES,
      crypto_aead_aegis128l_NPUBBYTES,
      crypto_aead_aegis128l_ABYTES,
      always_available
    },
#endif
#ifdef crypto_aead_aegis256_KEYBYTES
    {
      crypto_aead_aegis256_encrypt,
      crypto_aead_aegis256_decrypt,
      crypto_aead_aegis256_KEYBYTES,
      crypto_aead_aegis256_NPUBBYTES,
      crypto_aead_aegis256_ABYTES,
      always_available
    },
#endif
    {
      crypto_aead_aes256gcm_encrypt,
      crypto_aead_aes256gcm_decrypt,
      crypto_aead_aes256gcm_KEYBYTES,
      crypto_aead_aes256gcm_NPUBBYTES,
      crypto_aead_aes256gcm_ABYTES,
      crypto_aead_aes256gcm_is_available
    }
  };
  size_t num_algs = sizeof(algs) / sizeof(algs[0]);

  uint8_t choice = data[0] % num_algs;
  const AEAD_Algorithm &alg = algs[choice];

  if (alg.is_available && !alg.is_available()) {
      return 0;
  }

  if (size < 1 + alg.key_bytes + alg.npub_bytes) {
    return 0;
  }

  const unsigned char *k = data + 1;
  const unsigned char *npub = data + 1 + alg.key_bytes;
  const unsigned char *msg = data + 1 + alg.key_bytes + alg.npub_bytes;
  size_t total_msg_len = size - (1 + alg.key_bytes + alg.npub_bytes);

  // Split remaining data into message and associated data
  size_t ad_len = total_msg_len / 4;
  size_t msg_len = total_msg_len - ad_len;
  const unsigned char *ad = msg;
  msg += ad_len;

  // Limit lengths to avoid timeouts
  if (msg_len > 4096) msg_len = 4096;
  if (ad_len > 4096) ad_len = 4096;

  unsigned char *ciphertext = (unsigned char *) malloc(msg_len + alg.a_bytes);
  unsigned long long ciphertext_len;

  alg.encrypt(ciphertext, &ciphertext_len,
              msg, msg_len,
              ad, ad_len,
              NULL, npub, k);

  unsigned char *decrypted = (unsigned char *) malloc(msg_len + alg.a_bytes);
  unsigned long long decrypted_len;
  int err = alg.decrypt(decrypted, &decrypted_len,
                        NULL,
                        ciphertext, ciphertext_len,
                        ad, ad_len,
                        npub, k);
  
  if (err == 0) {
      assert(decrypted_len == msg_len);
      assert(memcmp(decrypted, msg, msg_len) == 0);
  }

  free(ciphertext);
  free(decrypted);

  return 0;
}

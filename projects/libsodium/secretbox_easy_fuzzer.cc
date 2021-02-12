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

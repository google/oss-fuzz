#include <assert.h>
#include <sodium.h>

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  assert(sodium_init() >= 0);

  unsigned char key[crypto_secretbox_KEYBYTES];
  unsigned char nonce[crypto_secretbox_NONCEBYTES];

  // make sure that seed is just a subset of the data
  unsigned char seed[randombytes_SEEDBYTES] = {       \
    'a', 's', 'e', 'e', 'd', 'a', 's', 'e', 'e', 'd', \
    'a', 's', 'e', 'e', 'd', 'a', 's', 'e', 'e', 'd', \
    'a', 's', 'e', 'e', 'd', 'a', 's', 'e', 'e', 'd', \
    'a', 's' };

  randombytes_buf_deterministic(key, crypto_secretbox_KEYBYTES, seed);
  randombytes_buf_deterministic(nonce, crypto_secretbox_NONCEBYTES, seed);

  size_t ciphertext_len = crypto_secretbox_MACBYTES + size;
  unsigned char ciphertext[ciphertext_len];

  crypto_secretbox_easy(ciphertext, data, size, nonce, key);

  unsigned char decrypted[size];
  crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce, key);

  return 0;
}

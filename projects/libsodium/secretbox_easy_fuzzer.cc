#include <assert.h>
#include <sodium.h>

const unsigned char key[crypto_secretbox_KEYBYTES] = {
  'k', 'e', 'y', 'k', 'e', 'y', 'k', 'e', 'y', 'k',
  'k', 'e', 'y', 'k', 'e', 'y', 'k', 'e', 'y', 'k',
  'k', 'e', 'y', 'k', 'e', 'y', 'k', 'e', 'y', 'k',
  'k', 'e'
};

const unsigned char nonce[crypto_secretbox_NONCEBYTES] = {
  'n', 'o', 'n', 'c', 'e', 'n', 'o', 'n', 'c', 'e',
  'n', 'o', 'n', 'c', 'e', 'n', 'o', 'n', 'c', 'e',
  'n', 'o', 'n', 'c',
};

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  assert(sodium_init() >= 0);

  size_t ciphertext_len = crypto_secretbox_MACBYTES + size;
  unsigned char ciphertext[ciphertext_len];

  crypto_secretbox_easy(ciphertext, data, size, nonce, key);

  unsigned char decrypted[size];
  crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce, key);

  return 0;
}

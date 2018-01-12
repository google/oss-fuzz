#include <assert.h>
#include <sodium.h>
#include <string.h>

#include "fake_random.h"

extern struct randombytes_implementation fake_random;

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  assert(randombytes_set_implementation(&fake_random) == 0);
  assert(randombytes_implementation_name() == "fake_random");
  assert(sodium_init() >= 0);

  unsigned char key[crypto_secretbox_KEYBYTES];
  unsigned char nonce[crypto_secretbox_NONCEBYTES];

  crypto_secretbox_keygen(key);
  randombytes_buf(nonce, sizeof nonce);

  size_t ciphertext_len = crypto_secretbox_MACBYTES + size;
  unsigned char ciphertext[ciphertext_len];

  crypto_secretbox_easy(ciphertext, data, size, nonce, key);

  unsigned char decrypted[size];
  crypto_secretbox_open_easy(decrypted, ciphertext, ciphertext_len, nonce, key);

  return 0;
}

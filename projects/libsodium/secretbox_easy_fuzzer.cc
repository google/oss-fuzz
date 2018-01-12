#include <assert.h>
#include <sodium.h>
#include <stdint.h>

// #include "fake_random.h"
// extern struct randombytes_implementation fake_random;

static const char *
fake_implementation_name(void) {
  return "fake_random";
}

static uint32_t
fake_randombytes(void) {
  return 0;
}

static void
fake_random_buffer(void * const buf, const size_t size) {
  static const unsigned char constant_seed[randombytes_SEEDBYTES] = {   \
    'N', 'O', 'T', 'E', 'S', 'T', 'D', 'A', 'T', 'A',                   \
    'N', 'O', 'T', 'E', 'S', 'T', 'D', 'A', 'T', 'A',                   \
    'N', 'O', 'T', 'E', 'S', 'T', 'D', 'A', 'T', 'A',                   \
    'N', '0'};
  randombytes_buf_deterministic(buf, size, constant_seed);
}

struct randombytes_implementation fake_random = {
  .implementation_name = fake_implementation_name,
  .random = fake_randombytes,
  .stir = NULL,
  .uniform = NULL,
  .buf = fake_random_buffer,
  .close = NULL
};

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

#include <assert.h>
#include <sodium.h>

// Test globals - I think this is awful, but it is all I can think of
const unsigned char *SEED;
size_t SEED_SIZE;

static const char *
fake_implementation_name(void) {
  return "fake_random";
}

static uint32_t
fake_random(void) {
  uint32_t r;
  return r;
}

static void
fake_buf(void * const buf, const size_t size) {}

static int
fake_close(void) {
  return 0;
}

struct randombytes_implementation fake_random_implementation = {
  SODIUM_C99(.implementation_name =) fake_implementation_name,
  SODIUM_C99(.random =) fake_random,
  SODIUM_C99(.stir =) NULL,
  SODIUM_C99(.uniform =) NULL,
  SODIUM_C99(.buf =) fake_buf,
  SODIUM_C99(.close =) fake_close
};


extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  SEED = data;
  SEED_SIZE = size;

  // pass data to a function that will be used as a seed for random
  // use that deterministic random to run the test.

  assert(randombytes_set_implementation(&fake_random_implementation) == 0);
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

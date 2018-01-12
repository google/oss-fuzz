#include <assert.h>
#include <sodium.h>
#include <string.h>

#include "fake_random.h"

// Globals - I think this is awful, but it is all I can think of
// const unsigned char *SEED;
// size_t SEED_SIZE;
//
// static const char *
// fake_implementation_name(void) {
//   return "fake_random";
// }
//
// static uint32_t
// fake_random(void) {
//   return 0;
// }
//
// static void
// fake_buf(void * const buf_, const size_t size) {
//   if (SEED_SIZE < randombytes_SEEDBYTES) {
//     // seed is too small
//     const unsigned char new_seed[randombytes_SEEDBYTES] = { \
//       'N', 'O', 'T', 'E', 'S', 'T', 'D', 'A', 'T', 'A',     \
//       'N', 'O', 'T', 'E', 'S', 'T', 'D', 'A', 'T', 'A',     \
//       'N', 'O', 'T', 'E', 'S', 'T', 'D', 'A', 'T', 'A',     \
//       'N', '0' };
//     randombytes_buf_deterministic(buf_, size, new_seed);
//   } else {
//     randombytes_buf_deterministic(buf_, size, SEED);
//   }
// }
//
// static int
// fake_close(void) {
//   return 0;
// }
//
// struct randombytes_implementation fake_random_implementation = {
//   .implementation_name = fake_implementation_name,
//   .random = NULL,
//   .stir = NULL,
//   .uniform = NULL,
//   .buf = fake_buf,
//   .close = NULL
// };

extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
  SEED = data;
  SEED_SIZE = size;

  // pass data to a function that will be used as a seed for random
  // use that deterministic random to run the test.

  // we don't want this to be an actual crasher, just a failure
  assert(randombytes_set_implementation(&fake_random_implementation) == 0);
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

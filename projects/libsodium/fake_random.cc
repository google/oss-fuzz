#include <sodium.h>
#include <string.h>

extern "C" {
  unsigned char *SEED;
  size_t SEED_SIZE;

  static const char *
  fake_implementation_name(void) {
    return "fake_random";
  }

  static void
  fake_buf(void * const buf_, const size_t size) {
    if (SEED_SIZE < randombytes_SEEDBYTES) {
      // seed is too small
      const unsigned char new_seed[randombytes_SEEDBYTES] = { \
        'N', 'O', 'T', 'E', 'S', 'T', 'D', 'A', 'T', 'A',     \
        'N', 'O', 'T', 'E', 'S', 'T', 'D', 'A', 'T', 'A',     \
        'N', 'O', 'T', 'E', 'S', 'T', 'D', 'A', 'T', 'A',     \
        'N', '0' };
      randombytes_buf_deterministic(buf_, size, new_seed);
    } else {
      randombytes_buf_deterministic(buf_, size, SEED);
    }
  }

  struct randombytes_implementation fake_random_implementation = {
    .implementation_name = fake_implementation_name,
    .random = NULL,
    .stir = NULL,
    .uniform = NULL,
    .buf = fake_buf,
    .close = NULL
  };
}

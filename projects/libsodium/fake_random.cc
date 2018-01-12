#include <sodium.h>
#include <string.h>

#include "fake_random.h"

static const char *
fake_implementation_name(void) {
  return "fake_random";
}

static unint32_t
fake_random(void) {
  return 0;
}

static void
fake_random_buffer(void * const buf, const size_t size) {
  const unsigned char new_seed[randombytes_SEEDBYTES] = {   \
    'N', 'O', 'T', 'E', 'S', 'T', 'D', 'A', 'T', 'A',       \
    'N', 'O', 'T', 'E', 'S', 'T', 'D', 'A', 'T', 'A',       \
    'N', 'O', 'T', 'E', 'S', 'T', 'D', 'A', 'T', 'A',       \
    'N', '0'};
  randombytes_buf_deterministic(buf, size, new_seed);
}

struct randombytes_implementation fake_random = {
  .implementation_name = fake_implementation_name,
  .random = fake_random,
  .stir = NULL,
  .uniform = NULL,
  .buf = fake_random_buffer,
  .close = NULL
};

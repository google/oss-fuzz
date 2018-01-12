#ifndef FAKE_RANDOM_H_
#define FAKE_RANDOM_H_

#include <sodium.h>
#include <stdint.h>

#include "fake_random.h"

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

#endif // FAKE_RANDOM_H_

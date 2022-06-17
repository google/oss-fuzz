// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef FAKE_RANDOM_H_
#define FAKE_RANDOM_H_

#include <sodium.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <algorithm>

static const unsigned char * SEED_DATA;
static size_t SEED_SIZE;

static const char *
fake_implementation_name(void) {
  return "fake_random";
}

static void
fake_random_buffer(void * const buf, const size_t size) {
  static unsigned char seed[randombytes_SEEDBYTES];
  memset(seed, '0', randombytes_SEEDBYTES);

  size_t boundary = std::min((size_t) randombytes_SEEDBYTES, SEED_SIZE);
  memcpy(&seed, SEED_DATA, boundary);

  randombytes_buf_deterministic(buf, size, seed);
}

struct randombytes_implementation fake_random = {
  .implementation_name = fake_implementation_name,
  .random = NULL,
  .stir = NULL,
  .uniform = NULL,
  .buf = fake_random_buffer,
  .close = NULL
};

void
setup_fake_random(const unsigned char * seed, const size_t seed_size) {
  SEED_DATA = seed;
  SEED_SIZE = seed_size;

  int fake_random_set = randombytes_set_implementation(&fake_random);
  assert(fake_random_set == 0);

  assert(strcmp(randombytes_implementation_name(), "fake_random") == 0);
  int initialized = sodium_init();
  assert(initialized >= 0);
}

#endif // FAKE_RANDOM_H_

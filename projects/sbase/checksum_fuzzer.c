/* Copyright 2024 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypt.h"
#include "md5.h"
#include "sha256.h"
#include "sha384.h"
#include "sha512-224.h"
#include "sha512-256.h"
#include "sha512.h"
#include "util.h"

static struct md5 ms;
struct crypt_ops md5_ops = {
    md5_init,
    md5_update,
    md5_sum,
    &ms,
};

static struct sha256 ss;
struct crypt_ops sha256_ops = {
    sha256_init,
    sha256_update,
    sha256_sum,
    &ss,
};

static struct sha384 s384;
struct crypt_ops sha384_ops = {
    sha384_init,
    sha384_update,
    sha384_sum,
    &s384,
};

static struct sha512_224 s224;
struct crypt_ops sha512_224_ops = {
    sha512_224_init,
    sha512_224_update,
    sha512_224_sum,
    &s224,
};

static struct sha512_256 s256;
struct crypt_ops sha512_256_ops = {
    sha512_256_init,
    sha512_256_update,
    sha512_256_sum,
    &s256,
};

static struct sha512 ss512;
struct crypt_ops sha512_ops = {
    sha512_init,
    sha512_update,
    sha512_sum,
    &ss512,
};

static char *fuzz_argv[3];
char *zero_arg = "path";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];
  if (size == 0) {
    return 0;
  }

  const uint8_t decider = data[0] % 6;
  data++;
  size--;

  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  uint8_t md[MD5_DIGEST_LENGTH];
  uint8_t sbuffer[SHA256_DIGEST_LENGTH];
  uint8_t s384_buffer[SHA384_DIGEST_LENGTH];
  uint8_t s512_224_buffer[SHA512_224_DIGEST_LENGTH];
  uint8_t s512_256_buffer[SHA512_256_DIGEST_LENGTH];
  uint8_t s512_buffer[SHA512_DIGEST_LENGTH];

  fuzz_argv[0] = filename;
  fuzz_argv[1] = filename;
  fuzz_argv[2] = NULL;

  switch (decider) {
  case 0: {
    cryptmain(2, fuzz_argv, &md5_ops, md, sizeof(md));
    break;
  }
  case 1: {
    cryptmain(2, fuzz_argv, &sha256_ops, sbuffer, sizeof(sbuffer));
    break;
  }
  case 2: {
    cryptmain(2, fuzz_argv, &sha384_ops, s384_buffer, sizeof(s384_buffer));
    break;
  }
  case 3: {
    cryptmain(2, fuzz_argv, &sha512_224_ops, s512_224_buffer,
              sizeof(s512_224_buffer));
    break;
  }
  case 4: {
    cryptmain(2, fuzz_argv, &sha512_256_ops, s512_256_buffer,
              sizeof(s512_256_buffer));
    break;
  }
  case 5: {
    cryptmain(2, fuzz_argv, &sha512_ops, s512_buffer, sizeof(s512_buffer));
    break;
  }
  default: {
    break;
  }
  }

  unlink(filename);

  return 0;
}

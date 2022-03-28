/* Copyright 2022 Google LLC
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

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

static const uint8_t *data;
static size_t dataLen;

static void check_compress_level(uint8_t *compr, size_t comprLen,
                                 uint8_t *uncompr, size_t uncomprLen,
                                 int level) {
  compress2(compr, &comprLen, data, dataLen, level);
  uncompress(uncompr, &uncomprLen, compr, comprLen);

  /* Make sure compress + uncompress gives back the input data. */
  assert(dataLen == uncomprLen);
  assert(0 == memcmp(data, uncompr, dataLen));
}

#define put_byte(s, i, c) {s[i] = (unsigned char)(c);}

static void write_zlib_header(uint8_t *s, unsigned compression_method, unsigned flags) {
  unsigned int header = (Z_DEFLATED + ((flags)<<4)) << 8;
  header |= (compression_method << 6);

  header += 31 - (header % 31);

  /* s is guaranteed to be longer than 2 bytes. */
  put_byte(s, 0, (unsigned char)(header >> 8));
  put_byte(s, 1, (unsigned char)(header & 0xff));
}

static void check_decompress(uint8_t *compr, size_t comprLen, unsigned compression_method, unsigned flags) {
  /* We need to write a valid zlib header of size two bytes. Copy the input data
     in a larger buffer. Do not modify the input data to avoid libFuzzer error:
     fuzz target overwrites its const input. */
  size_t copyLen = dataLen + 2;
  uint8_t *copy = (uint8_t *)malloc(copyLen);
  memcpy(copy + 2, data, dataLen);
  write_zlib_header(copy, compression_method, flags);

  uncompress(compr, &comprLen, copy, copyLen);
  free(copy);
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t size) {
  if (size < 10 || size > 1024 * 1024)
    return 0;

  const int level = d[0] % 10;
  d++,size--;
  
  //https://web.archive.org/web/20200220015003/http://www.onicos.com/staff/iz/formats/gzip.html
  unsigned compression_method = d[0] % 5;
  if (compression_method == 4)  //[4...7] are reserved
    compression_method = 8;
  d++,size--;
  unsigned flags = d[0] & (2 << 4);
  d++,size--;

  size_t comprLen = compressBound(size);
  size_t uncomprLen = size;
  uint8_t *compr, *uncompr;

  data = d;
  dataLen = size;
  compr = (uint8_t *)calloc(1, comprLen);
  if (!compr)
    goto err;
  uncompr = (uint8_t *)calloc(1, uncomprLen);
  if (!uncompr)
    goto err;

  check_compress_level(compr, comprLen, uncompr, uncomprLen, level);
  check_decompress(compr, comprLen, compression_method, flags);

err:
  free(compr);
  free(uncompr);

  /* This function must return 0. */
  return 0;
}

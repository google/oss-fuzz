/*
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
*/

#include "bzlib.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

static void fuzzer_write_data(FILE *file, const uint8_t *data, size_t size) {
  int    bzerr         = 0;
  int    blockSize100k = 9;
  int    verbosity     = 0;
  int    workFactor    = 30;
  unsigned int nbytes_in_lo32, nbytes_in_hi32;
  unsigned int nbytes_out_lo32, nbytes_out_hi32;

  BZFILE* bzf = BZ2_bzWriteOpen(&bzerr, file,
                           blockSize100k, verbosity, workFactor);
  if (bzerr != BZ_OK) return;

  /* Use low-level BZ2_bzWrite (was incorrectly using high-level BZ2_bzwrite) */
  BZ2_bzWrite(&bzerr, bzf, (void*)data, size);

  BZ2_bzWriteClose64(&bzerr, bzf, 0,
                      &nbytes_in_lo32, &nbytes_in_hi32,
                      &nbytes_out_lo32, &nbytes_out_hi32);
}

static void fuzzer_read_data(const int file_descriptor) {
  int    bzerr         = 0;
  char   obuf[BZ_MAX_UNUSED];

  BZFILE* bzf2 = BZ2_bzdopen(file_descriptor, "rb");
  if (!bzf2) return;

  while (bzerr == BZ_OK) {
      int nread = BZ2_bzRead(&bzerr, bzf2, obuf, BZ_MAX_UNUSED);
      if (nread == 0 && bzerr == BZ_OK) break;
  }

  BZ2_bzclose(bzf2);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char* filename = strdup("/tmp/generate_temporary_file.XXXXXX");
  if (!filename) {
    return 0;
  }
  const int file_descriptor = mkstemp(filename);
  if (file_descriptor < 0) {
    free(filename);
    return 0;
  }
  FILE* file = fdopen(file_descriptor, "wb");

  if (!file) {
    close(file_descriptor);
    free(filename);
    return 0;
  }

  fuzzer_write_data(file, data, size);

  fflush(file);

  int read_fd = open(filename, O_RDONLY);
  if (read_fd >= 0) {
    fuzzer_read_data(read_fd);
  }

  /* Removed BZ2_bzflush(file) - it expects BZFILE*, not FILE* */
  fclose(file);

  unlink(filename);
  free(filename);
  return 0;
}

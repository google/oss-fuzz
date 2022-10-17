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
#include <assert.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>

extern BZFILE* BZ2_bzWriteOpen(
  int*  bzerror,
  FILE* f,
  int   blockSize100k,
  int   verbosity,
  int   workFactor );

extern BZFILE* BZ2_bzReadOpen(
  int*  bzerror,
  FILE* f,
  int   verbosity,
  int   small,
  void* unused,
  int   nUnused );

static void fuzzer_write_data(FILE *file, const uint8_t *data, size_t size) {
  int    bzerr;
  int    blockSize100k = 9;
  int    verbosity     = 0;
  int    workFactor    = 30;
  uint   nbytes_in_lo32, nbytes_in_hi32;
  uint   nbytes_out_lo32, nbytes_out_hi32;

  BZFILE* bzf = BZ2_bzWriteOpen ( &bzerr, file,
                           blockSize100k, verbosity, workFactor );

  BZ2_bzWrite (&bzerr, bzf, (void*)data, size);

  BZ2_bzWriteClose64 ( &bzerr, bzf, 0,
                        &nbytes_in_lo32, &nbytes_in_hi32,
                        &nbytes_out_lo32, &nbytes_out_hi32 );
}

static void fuzzer_read_data(FILE *file) {
  int    bzerr;
  int    verbosity = 0;
  char   obuf[BZ_MAX_UNUSED];
  char   unused[BZ_MAX_UNUSED];
  int    nUnused = 0;
  bool   smallMode = 0;

  BZFILE* bzf2 = BZ2_bzReadOpen (&bzerr, file, verbosity, (int)smallMode, unused, nUnused);

  while (bzerr == BZ_OK) {
      BZ2_bzRead ( &bzerr, bzf2, obuf, BZ_MAX_UNUSED);
  }

  BZ2_bzReadClose ( &bzerr, bzf2);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char* filename = strdup("/tmp/generate_temporary_file.XXXXXX");
  if (!filename) {
    perror("Failed to allocate file name buffer.");
    abort();
  }
  const int file_descriptor = mkstemp(filename);
  if (file_descriptor < 0) {
    perror("Failed to make temporary file.");
    abort();
  }
  FILE* file = fdopen(file_descriptor, "wb");
  if (!file) {
    perror("Failed to open file descriptor.");
    close(file_descriptor);
    abort();
  }
  
  fuzzer_write_data(file, data, size);

  fuzzer_read_data(file);

  fclose(file);

  if (unlink(filename) != 0) {
    perror("WARNING: Failed to delete temporary file.");
  }
  free(filename);
  return 0;
}
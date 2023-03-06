/* Copyright 2021 Google LLC
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

/*
 * We convert addr2line.c into a header file to make convenient for fuzzing.
 * We do this for several of the binutils applications when creating
 * the binutils fuzzers.
 */
#include "fuzz_addr2line.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  program_name = filename;

  char **c2 = malloc(sizeof(char*)*6);
  char *c2_1 = strdup("AAABC");
  char *c2_2 = strdup("BBC");
  char *c2_3 = strdup("0xbeefbeef");
  char *c2_4 = strdup("0xcafebabe");
  char *c2_5 = strdup("5123423");
  c2[0] = c2_1;
  c2[1] = c2_2;
  c2[2] = c2_3;
  c2[3] = c2_4;
  c2[4] = c2_5;
  c2[5] = NULL;

  naddr  = 2;
  addr = c2;

  // Main fuzz entrypoint in addr2line.c
  process_file(filename, NULL, NULL);
 
  free(c2);
  free(c2_1);
  free(c2_2);
  free(c2_3);
  free(c2_4);
  free(c2_5);

  unlink(filename);
  return 0;
}

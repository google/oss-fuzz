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
 * We convert objcopy.c into a header file to make convenient for fuzzing.
 * We do this for several of the binutils applications when creating
 * the binutils fuzzers.
 */
#include "fuzz_objcopy.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

static int initialized = 0;

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

  if (initialized == 0) {
    if (bfd_init () != BFD_INIT_MAGIC) {
      abort();
    }
    set_default_bfd_target();
    initialized = 1;
  }


  create_symbol_htabs();

  char *fakeArgv[4];
  fakeArgv[0] = "fuzz_objdump";
  fakeArgv[1] = filename;
  fakeArgv[2] = "/tmp/random.out";
  fakeArgv[3] = NULL;
  copy_main(3, fakeArgv);

  // Cleanup
  free (strip_specific_buffer);
  strip_specific_buffer = NULL;
  free (strip_unneeded_buffer);
  strip_unneeded_buffer = NULL;
  free (keep_specific_buffer);
  keep_specific_buffer = NULL;
  free (localize_specific_buffer);
  localize_specific_buffer = NULL;
  free (globalize_specific_buffer);
  globalize_specific_buffer = NULL;
  free (keepglobal_specific_buffer);
  keepglobal_specific_buffer = NULL;
  free (weaken_specific_buffer);
  weaken_specific_buffer = NULL;

  unlink(filename);
  remove("/tmp/random.out");
  return 0;
}


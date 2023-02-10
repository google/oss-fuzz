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
 * Fuzzer that targets load_separate_debug_files in dwarf.c
 * To do this we rely on some of the logic in objdump.c
 */
#include "fuzz_objdump.h"

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

  bfd *file;
  file = bfd_openr (filename, NULL);
  if (file) {
  if (bfd_check_format (file, bfd_object)) {
    load_separate_debug_files(file, bfd_get_filename(file));
    }
  }
  unlink(filename);
  return 0;
}

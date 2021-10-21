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
 * We convert objdump.c into a header file to make convenient for fuzzing.
 * We do this for several of the binutils applications when creating
 * the binutils fuzzers.
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

  process_links = true;
  do_follow_links = true;
  dump_section_contents = true;
  dump_section_headers = true;
  dump_private_headers = true;
  dump_ar_hdrs = true;
  dump_reloc_info = true;
  dump_dynamic_reloc_info = true;

  // Main fuzz entrypoint in objdump.c
  display_file(filename, NULL, true);

  unlink(filename);
  return 0;
}

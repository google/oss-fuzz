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
 * We convert strings.c into a header file to make convenient for fuzzing.
 * We do this for several of the binutils applications when creating
 * the binutils fuzzers.
 */
#include "fuzz_strings.h"

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

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  program_name = "fuzz_strings";
  xmalloc_set_program_name (program_name);
  bfd_set_error_program_name (program_name);


  string_min = 4;
  include_all_whitespace = false;
  print_addresses = false;
  print_filenames = false;
  datasection_only = true;
  target = NULL;
  encoding = 's';
  output_separator = NULL;
  encoding_bytes = 1;

  if (bfd_init () != BFD_INIT_MAGIC)
    fatal (_("fatal error: libbfd ABI mismatch"));
  set_default_bfd_target ();


  // Main fuzz entrypoint in strings.c
  strings_object_file(filename);

  unlink(filename);
  return 0;
}

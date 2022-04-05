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
 * We convert as.c into a header file to make convenient for fuzzing.
 * We do this for several of the binutils applications when creating
 * the binutils fuzzers.
 */
#include <fuzz_as.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer-%d.s", getpid());
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  reg_section = NULL;

  const char *fakeArgv[3];
  fakeArgv[0] = "fuzz_objdump";
  fakeArgv[1] = filename; // Assemble our fake source file.
  fakeArgv[2] = NULL;

  out_file_name = "/tmp/tmp-out";

  // as initialition. This follows the flow of ordinary main function
  symbol_begin ();
  frag_init ();
  subsegs_begin ();
  read_begin ();
  input_scrub_begin ();
  expr_begin ();
  macro_init (flag_macro_alternate, flag_mri, 0, macro_expr);

  output_file_create (out_file_name);
  itbl_init ();
  dwarf2_init ();
  cond_finish_check (-1);

  dot_symbol_init ();

  // Main fuzzer target. Assemble our random data.
  perform_an_assembly_pass (2, (char**)fakeArgv);

  // Cleanup
  cond_finish_check (-1);
  dwarf2_finish ();
  cfi_finish ();
  input_scrub_end ();

  unlink(filename);

  return 0;
}

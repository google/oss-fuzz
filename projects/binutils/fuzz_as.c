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

/* Don't allow cleanups.  libiberty's function of the same name adds
   cleanups to a list without any means of clearing the list.  The
   list must be clear at the start if LLVMFuzzerTestOneInput is to run
   more than once, otherwise we will get multiple copies of the same
   cleanup on the list which leads to double frees if xexit is called.
   Also a cleanup from the first run can result in use-after-free
   errors when as_fatal is hit as in issue 56429.  */
int
xatexit (void (*fn) (void) ATTRIBUTE_UNUSED)
{
  return 0;
}

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

  char *fakeArgv[3];
  fakeArgv[0] = "fuzz_as";
  fakeArgv[1] = filename; // Assemble our fake source file.
  fakeArgv[2] = NULL;

  int argc = 2;
  char **argv = fakeArgv;
  gas_early_init (&argc, &argv);

  out_file_name = "/tmp/tmp-out";

  gas_init ();

  // Main fuzzer target. Assemble our random data.
  perform_an_assembly_pass (argc, argv);

  // Cleanup
  cond_finish_check (-1);
  codeview_finish ();
  dwarf2_finish ();
  cfi_finish ();
  input_scrub_end ();

  keep_it = 0;
  output_file_close ();
  free_notes ();
  unlink(filename);

  return 0;
}

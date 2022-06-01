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
 * We convert dlltool.c into a header file to make convenient for fuzzing.
 * We do this for several of the binutils applications when creating
 * the binutils fuzzers.
 */
#include "fuzz_dlltool.h"

void
init_dlltool_global_state() {
  import_list = NULL;
  as_name = NULL;
  as_flags = "";
  tmp_prefix = NULL;
  exp_name = NULL;
  imp_name = NULL;
  delayimp_name = NULL;
  identify_imp_name = NULL;
  identify_strict = NULL;
  head_label = NULL;
  imp_name_lab = NULL;
  dll_name = NULL;
  add_indirect = 0;
  add_underscore = 0;
  add_stdcall_underscore = 0;
  leading_underscore = -1;
  dontdeltemps = 0;
  do_default_excludes = true;
  use_nul_prefixed_import_tables = false;
  def_file = NULL;
}

void callIntoDlltool(char *, char*, bool);
void
callIntoDlltool(char *deffile, char *objfile, bool var_export_all_symbols) {
  init_dlltool_global_state();
  program_name = "fuzz_dlltool";
  mname = "mcore-elf";
  export_all_symbols = var_export_all_symbols;

  // At the moment we focus on the def file processing
  def_file = deffile;
  process_def_file(deffile);
  scan_obj_file(objfile);
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 512) {
    return 0;
  }

  /* def file */
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, 412, 1, fp);
  fclose(fp);

  data += 412;
  size -= 412;

  char filename2[256];
  sprintf(filename2, "/tmp/libfuzzer-2.%d", getpid());
  FILE *fp2 = fopen(filename2, "wb");
  if (!fp2) {
    return 0;
  }

  fwrite(data, size, 1, fp2);
  fclose(fp2);

  callIntoDlltool(filename, filename2, true);
  callIntoDlltool(filename, filename2, false);

  unlink(filename);
  unlink(filename2);
  return 0;
}

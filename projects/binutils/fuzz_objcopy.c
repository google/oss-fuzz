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

void
init_objcopy_global_state() {
  // status is a global variable that is set to 0 initially,
  // and we should ensure the state is not maintained for each iteration.
  status = 0;
  pe_file_alignment = (bfd_vma) -1;
  pe_heap_commit = (bfd_vma) -1;
  pe_heap_reserve = (bfd_vma) -1;
  pe_image_base = (bfd_vma) -1;
  pe_section_alignment = (bfd_vma) -1;
  pe_stack_commit = (bfd_vma) -1;
  pe_stack_reserve = (bfd_vma) -1;
  pe_subsystem = -1;
  pe_major_subsystem_version = -1;
  pe_minor_subsystem_version = -1;
  section_rename_list = NULL;
  isympp = NULL;
  osympp = NULL;
  copy_byte = -1;
  interleave = 0;
  copy_width = 1;
  keep_section_symbols = false;
  deterministic = -1;
  status = 0;
  merge_notes = false;
  strip_symbols = STRIP_UNDEF;
  change_sections = NULL;
  change_start = 0;
  set_start_set = false;
  change_section_address = 0;
  gap_fill_set = false;
  gap_fill = 0;
  pad_to_set = false;
  use_alt_mach_code = 0;
  add_sections = NULL;
  update_sections = NULL;
  dump_sections = NULL;
  gnu_debuglink_filename = NULL;
  convert_debugging = false;
  change_leading_char = false;
  remove_leading_char = false;
  wildcard = false;
  localize_hidden = false;
  strip_specific_htab = NULL;
  strip_unneeded_htab = NULL;
  keep_specific_htab = NULL;
  localize_specific_htab = NULL;
  globalize_specific_htab = NULL;
  keepglobal_specific_htab = NULL;
  weaken_specific_htab = NULL;
  redefine_specific_htab = NULL;
  redefine_specific_reverse_htab = NULL;
  add_sym_tail = &add_sym_list;
  add_symbols = 0;
  strip_specific_buffer = NULL;
  strip_unneeded_buffer = NULL;
  keep_specific_buffer = NULL;
  localize_specific_buffer = NULL;
  globalize_specific_buffer = NULL;
  keepglobal_specific_buffer = NULL;
  weaken_specific_buffer = NULL;
  weaken = false;
  keep_file_symbols = false;
  prefix_symbols_string = 0;
  prefix_sections_string = 0;
  prefix_alloc_sections_string = 0;
  extract_symbol = false;

  create_symbol_htabs();
}

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

  if (bfd_init() != BFD_INIT_MAGIC)
    abort();

  set_default_bfd_target();

  init_objcopy_global_state();

  /* glibc getopt has internal static state.  Setting optind to zero
     reinitialises it.  Do this every second run, which effectively
     alternates objcopy with options then objcopy without options.
     (optind will be 9 when copy_main returns.)  */
  static int iter;
  if (++iter & 1)
    optind = 0;

  char *fakeArgv[12];
  fakeArgv[0] = "fuzz_objcopy";
  fakeArgv[1] = "-S";
  fakeArgv[2] = "--decompress-debug-sections";
  fakeArgv[3] = "--extract-dwo";
  fakeArgv[4] = "--merge-notes";
  fakeArgv[5] = "--pure";
  fakeArgv[6] = "--debugging";
  fakeArgv[7] = "--compress-debug-sections";
  fakeArgv[8] = "--extract-symbol";
  fakeArgv[9] = filename;
  fakeArgv[10] = "/tmp/random.out";
  fakeArgv[11] = NULL;
  copy_main(11, fakeArgv);

  // Cleanup
  free (strip_specific_buffer);
  free (strip_unneeded_buffer);
  free (keep_specific_buffer);
  free (localize_specific_buffer);
  free (globalize_specific_buffer);
  free (keepglobal_specific_buffer);
  free (weaken_specific_buffer);
  delete_symbol_htabs ();

  unlink(filename);
  remove("/tmp/random.out");
  return 0;
}


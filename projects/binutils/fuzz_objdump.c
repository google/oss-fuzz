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

void objdump_reset() {
  process_links = true;
  do_follow_links = true;
  dump_section_contents = true;
  dump_section_headers = true;
  dump_private_headers = true;
  dump_ar_hdrs = true;
  dump_dwarf_section_info = true;
  // We must call both dwarf_select_sections_by_letters and dwarf_select_sections_all
  // since dwarf_select_sections_all does not set do_debug_lines |= FLAG_DEBUG_LINES_DECODED;
  dwarf_select_sections_by_letters("L");
  dwarf_select_sections_all ();
  dump_debugging = true;

  dump_stab_section_info = true;
  disassemble_all = true;
}

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

  objdump_reset();

  // These flags contain a large set of calls to bfd_fatal (which calls
  // exit), so to enable fuzzing of objdump with a fuzzer that lives for
  // a longer period of time (more than 10 seconds) define
  // OBJDUMP_SAFE
#ifndef OBJDUMP_SAFE
  dump_reloc_info = true;
  // ctf section and reloc are simply too quick to exit and disrupts
  // fuzzing too much. Will leave this commented out for now.
  //dump_dynamic_reloc_info = true;
  //dump_ctf_section_info = true;
  disassemble = true;
#endif

  // Main fuzz entrypoint in objdump.c
  display_file(filename, NULL, true);

  unlink(filename);
  return 0;
}

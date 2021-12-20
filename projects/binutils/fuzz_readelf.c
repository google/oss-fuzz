/* Copyright 2020 Google Inc.

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
 * We convert readelf.c into a header file to make convenient for fuzzing.
 * We do this for several of the binutils applications when creating
 * the binutils fuzzers.
 */
#include "readelf.h"

#include "bfd.h"
#include "libbfd.h"

int check_architecture(char *tmpfilename, char *arch_string) {
  bfd_cleanup cleanup = NULL;
  bfd *file = bfd_openr(tmpfilename, arch_string);
  if (file == NULL) {
    remove(tmpfilename);
    return 0;
  }

  if (!bfd_read_p(file) ||
      (unsigned int)file->format >= (unsigned int)bfd_type_end) {
    bfd_close(file);
    return 0;
  }

  bool doAnalysis = false;
  if (bfd_seek(file, (file_ptr)0, SEEK_SET) == 0) {
    file->format = bfd_object;
    cleanup = BFD_SEND_FMT(file, _bfd_check_format, (file));
    if (cleanup) {
      doAnalysis = true;
      cleanup(file);
    }
    file->format = bfd_unknown;
  }

  if (file != NULL) {
    bfd_close(file);
  }

  // return 1 if the architecture matches.
  if (doAnalysis) {
    return 1;
  }
  return 0;
}

// int gb=0;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp)
    return 0;

    /* Code to quickly extract target list.
     * This is used to identify new targets but should
     * not be in the fuzz code.
    if (gb == 0) {
      char **doublel = bfd_target_list();
      while (*doublel != NULL) {
        printf("Target: %s\n", *doublel);
        doublel++;
      }
      gb=1;
    }
    exit(0);
    */

#ifdef READELF_TARGETED
  if (check_architecture(filename, READELF_TARGETED) == 0) {
    unlink(filename);
    return 0;
  }
#endif

  fwrite(data, size, 1, fp);
  fclose(fp);
  do_syms = true;
  do_reloc = true;
  do_unwind = true;
  do_dynamic = true;
  do_header = true;
  do_sections = true;
  do_section_groups = true;
  do_segments = true;
  do_version = true;
  do_histogram = true;
  do_arch = true;
  do_notes = true;

  // Enable DWARF analysis
  // We must call both dwarf_select_sections_by_letters and
  // dwarf_select_sections_all since dwarf_select_sections_all does not set
  // do_debug_lines |= FLAG_DEBUG_LINES_DECODED;
  dwarf_select_sections_by_letters("L");
  dwarf_select_sections_all();

  // Main fuzz entrypoint
  process_file(filename);

  unlink(filename);

  free(dump_ctf_symtab_name);
  dump_ctf_symtab_name = NULL;
  free(dump_ctf_strtab_name);
  dump_ctf_strtab_name = NULL;
  free(dump_ctf_parent_name);
  dump_ctf_parent_name = NULL;

  return 0;
}

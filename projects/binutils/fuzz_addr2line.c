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
 * We convert addr2line.c into a header file to make convenient for fuzzing.
 * We do this for several of the binutils applications when creating
 * the binutils fuzzers.
 */
#include "fuzz_addr2line.h"

/*
 * Preconditions that should be met so we won't run into bfd_fatal calls.
 * The fuzz_slurp_symtab and fuzz_preconditions_check implement simplified
 * versions of process_file and slurp_symtab of addr2line that only incorporates
 * the logic resulting in bfd_fatal calls.
 * If fuzz_preconditions_check returns 1, it means process_file should be
 * good to be called and there won't be any bfd_fatal call.
 */

int fuzz_slurp_symtab(bfd *abfd) {
  long storage;
  long symcount;
  bool dynamic = false;

  if ((bfd_get_file_flags (abfd) & HAS_SYMS) == 0) {
    return 1;
  }  
  storage = bfd_get_symtab_upper_bound (abfd);
  if (storage == 0) {
    storage = bfd_get_dynamic_symtab_upper_bound (abfd);
    dynamic = true;
  }
  if (storage < 0) {
    return 0;
  }

  syms = (asymbol **) xmalloc (storage);
  if (dynamic) {
    symcount = bfd_canonicalize_dynamic_symtab (abfd, syms);
  }
  else {
    symcount = bfd_canonicalize_symtab (abfd, syms);
  }

  if (symcount < 0) {
    free(syms);
    syms = NULL;
    return 0;
  }
  free(syms);
  syms = NULL;
  return 1;
}

int fuzz_preconditions_check(const char *file_name, const char *target) {
  bfd *abfd;
  char **matching;

  if (get_file_size (file_name) < 1) {
    return 0;
  }

  abfd = bfd_openr (file_name, target);
  if (abfd == NULL) {
    /* In this specific case just exit the fuzzer */
    bfd_fatal (file_name);
  }

  abfd->flags |= BFD_DECOMPRESS;
  if (bfd_check_format (abfd, bfd_archive)) {
    bfd_close(abfd);
    return 0;
  }

  if (! bfd_check_format_matches (abfd, bfd_object, &matching)) {
    bfd_close(abfd);
    return 0;
  }

  /* Check if slurp_symtab will exit */
  int retval = fuzz_slurp_symtab(abfd);
  bfd_close(abfd);
  return retval;
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

  char **c2 = malloc(sizeof(char*)*6);
  char *c2_1 = strdup("AAABC");
  char *c2_2 = strdup("BBC");
  char *c2_3 = strdup("0xbeefbeef");
  char *c2_4 = strdup("0xcafebabe");
  char *c2_5 = strdup("5123423");
  c2[0] = c2_1;
  c2[1] = c2_2;
  c2[2] = c2_3;
  c2[3] = c2_4;
  c2[4] = c2_5;
  c2[5] = NULL;

  naddr  = 2;
  addr = c2;

  // Main fuzz entrypoint in addr2line.c
  if (fuzz_preconditions_check(filename, NULL) == 1) {
    process_file(filename, NULL, NULL);
  }
 
  free(c2);
  free(c2_1);
  free(c2_2);
  free(c2_3);
  free(c2_4);
  free(c2_5);

  unlink(filename);
  return 0;
}

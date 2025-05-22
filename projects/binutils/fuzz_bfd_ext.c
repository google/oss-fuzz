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
 * This is an example fuzzer targeted a given architecture. The point of this is
 * that the general fuzz_bfd fuzzer has too large reacability which makes it
 * difficult to reach the entire codebase in practice. The goal is to create
 * more targeted fuzzers that are more likely to explore a given code area.
 *
 */
#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static int bufferToFile(char *name, const uint8_t *Data, size_t Size) {
  int fd = mkstemp(name);
  if (fd < 0) {
    printf("failed mkstemp, errno=%d\n", errno);
    return -2;
  }
  if (write(fd, Data, Size) != Size) {
    printf("failed write, errno=%d\n", errno);
    close(fd);
    return -3;
  }
  close(fd);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  char tmpfilename[32];

  if (bfd_init() != BFD_INIT_MAGIC)
    abort();

  /*
      char **names = bfd_target_list();
      while (*names != NULL) {
        printf("Name: %s\n", *names);
        names++;
      }
  */

  bfd_cleanup cleanup = NULL;

  strncpy(tmpfilename, "/tmp/fuzz.bfd-XXXXXX", 31);
  if (bufferToFile(tmpfilename, Data, Size) < 0) {
    return 0;
  }
  // bfd *file = bfd_openr (tmpfilename, "elf32-frv");
  bfd *file = bfd_openr(tmpfilename, "pef");
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

  if (doAnalysis) {
    // We have a file with the target data we want.
    // Let's open as a write file this time, which should trigger
    // more actions on the code when calling bfd_close.
    // TODO: do more processing on this, e.g. use the file as
    // input to some of the other utilities.
    bfd *wFile = bfd_openw(tmpfilename, "pef");
    if (file != NULL) {
      bfd_close(wFile);
    }
  }

  remove(tmpfilename);
  return 0;
}

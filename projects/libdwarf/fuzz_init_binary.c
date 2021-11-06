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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "dwarf.h"
#include "libdwarf.h"
#include "libdwarf_private.h"
#include "dwarf_alloc.h"


/*
 * A fuzzer that simulates a small part of the simplereader.c example.
 * This fuzzer targets dwarf_init_b.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  int my_init_fd = 0;
  Dwarf_Ptr errarg = 0;
  Dwarf_Handler errhand = 0;
  Dwarf_Error *errp = NULL;
  Dwarf_Debug dbg = 0;

  my_init_fd = open(filename, O_RDONLY);
  if (my_init_fd != -1) {
    dwarf_init_b(my_init_fd,DW_GROUPNUMBER_ANY,errhand,errarg,&dbg,errp);
    dwarf_finish(dbg);
    close(my_init_fd);
  }

  unlink(filename);
  return 0;
}

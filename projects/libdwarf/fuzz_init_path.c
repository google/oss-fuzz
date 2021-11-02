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
#include "dwarf.h"
#include "dwarfstring.h"
#include "libdwarf.h"
#include "libdwarf_private.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);
  Dwarf_Ptr errarg = 0;
  Dwarf_Handler errhand = 0;
  Dwarf_Debug dbg = 0;
  Dwarf_Error *errp = 0;
#define MACHO_PATH_LEN 2000
  char macho_real_path[2000];
  dwarf_init_path(filename, macho_real_path, MACHO_PATH_LEN, DW_DLC_READ,
                  DW_GROUPNUMBER_ANY, errhand, errarg, &dbg, 0, 0, 0, errp);

  unlink(filename);
  return 0;
}

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
#include <stdlib.h>
#include <stdio.h>

#include "system.h"

#include <popt.h>
#include <rpm/rpmcli.h>
#include <rpm/rpmdb.h>
#include "cliutils.h"
#include "debug.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  xsetprogname("fuzz_header");
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  FD_t fd = Fopen(filename, "rb");
  Header h = headerRead(fd, 0xAA);
  headerFree(h);
  Fclose(fd);

  unlink(filename);
  return 0;
}

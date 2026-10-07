/* Copyright 2022 Google LLC
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

#include <assert.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "libdwfl.h"
#include "system.h"

static const char *debuginfo_path = "";
static const Dwfl_Callbacks cb  = {
  NULL,
  dwfl_standard_find_debuginfo,
  NULL,
  (char **)&debuginfo_path,
};


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[] = "/tmp/fuzz-libdwfl.XXXXXX";
  int fd;
  ssize_t n;

  fd = mkstemp(filename);
  assert(fd >= 0);

  n = write_retry(fd, data, size);
  assert(n == (ssize_t) size);

  close(fd);

  Dwarf_Addr bias = 0;
  Dwfl *dwfl = dwfl_begin(&cb);
  dwfl_report_begin(dwfl);

  Dwfl_Module *mod = dwfl_report_offline(dwfl, filename, filename, -1);
  dwfl_module_getdwarf(mod, &bias);

  dwfl_end (dwfl);
  unlink(filename);
  return 0;
}

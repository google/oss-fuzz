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
 * The goal of this fuzzer is to simulate the logic for ranlib. We implement the
 * fuzzer without calling ar.c itself in order to avoid bfd_fatal calls.
 */
#include "sysdep.h"
#include "bfd.h"
#include "libiberty.h"
#include "getopt.h"
#include "aout/ar.h"
#include "bucomm.h"
#include "arsup.h"
#include "filenames.h"
#include "binemul.h"
#include "plugin-api.h"
#include "plugin.h"
#include "ansidecl.h"

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

  int f;
  bfd *arch;

  f = open (filename, O_RDWR | O_BINARY, 0);
  if (f < 0) {
    return 0;
  }

  arch = bfd_fdopenr (filename, (const char *) NULL, f);
  if (arch == NULL) {
    close(f);
    return 0;
  }
  if (! bfd_check_format (arch, bfd_archive)) {
    bfd_close(arch);
    return 0;
  }

  if (! bfd_has_map (arch)) {
    bfd_close(arch);
    return 0;
  }

  bfd_is_thin_archive (arch);

  bfd_update_armap_timestamp(arch);
  bfd_close(arch);

  unlink(filename);
  return 0;
}

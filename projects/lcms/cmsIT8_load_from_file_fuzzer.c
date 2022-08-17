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

#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include "lcms2.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0)
    return 0;

  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d.icc", getpid());
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  cmsHANDLE handle = cmsIT8LoadFromFile(0, filename);

  if (handle) {
    // Anything that is loaded should be able to save.
    cmsIT8SaveToFile(handle, "TEST.IT8");
    cmsIT8Free(handle);
  }

  unlink(filename);

  return 0;
}

// Copyright 2016 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include "lcms2.h"

// The main sink
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0)
    return 0;

  cmsHANDLE handle = cmsIT8LoadFromMem(0, (void *)data, size);
  if (handle) {
    char filename[256];
    sprintf(filename, "/tmp/fuzzer-it.%d.it8", getpid());
    cmsIT8SaveToFile(handle, filename);

    cmsIT8Free(handle);
  }

  return 0;
}

// Copyright 2018 Google Inc.
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
/////////////////////////////////////////////////////////////////////////////

#include <stdint.h>
#include "gd.h"

#define PASTE(x) gdImageCreateFrom ## x ## Ptr
#define CREATE_IMAGE(FORMAT) PASTE(FORMAT)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    gdImagePtr im = CREATE_IMAGE(FUZZ_GD_FORMAT)(Size, (void*) Data);
    if (im) gdImageDestroy(im);
    return 0;
}

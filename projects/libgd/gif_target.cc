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

const uint32_t MAX_PIXEL_SIZE = 10000;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    gdImagePtr im;

    if (Size > 10) {
        uint32_t width, height;
        width = Data[7] + (Data[8] << 8);
        height = Data[9] + (Data[10] << 8);
        if (width * height > MAX_PIXEL_SIZE) {
            return 0;
        }
    }

    im = gdImageCreateFromGifPtr(Size, (void*) Data);
    if (im) gdImageDestroy(im);
    return 0;
}

// Copyright 2020 Google Inc.
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

#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

#include "gd.h"
#include "gdfontg.h"
#include "gdfontl.h"
#include "gdfontmb.h"
#include "gdfonts.h"
#include "gdfontt.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider stream(data, size);
    const uint8_t slate_width = stream.ConsumeIntegral<uint8_t>();
    const uint8_t slate_height = stream.ConsumeIntegral<uint8_t>();
    gdImagePtr slate_image = gdImageCreateTrueColor(slate_width, slate_height);
    if (slate_image == nullptr) {
      return 0;
    }

    const int x_position = stream.ConsumeIntegral<int>();
    const int y_position = stream.ConsumeIntegral<int>();
    const int text_color = stream.ConsumeIntegral<int>();
    const gdFontPtr font_ptr = stream.PickValueInArray(
        {gdFontGetGiant(), gdFontGetLarge(), gdFontGetMediumBold(),
        gdFontGetSmall(), gdFontGetTiny()});
    const std::string text = stream.ConsumeRemainingBytesAsString();

    gdImageString(slate_image, font_ptr, x_position, y_position,
                  reinterpret_cast<uint8_t*>(const_cast<char*>(text.c_str())),
                  text_color);
    gdImageDestroy(slate_image);
    return 0;
}

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
// TODO(kjlubick): Move this into Skia proper


#include "SkCanvas.h"
#include "SkBitmap.h"
#include "SkImageFilter.h"
#include "SkPaint.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const int BitmapSize = 24;
    SkBitmap bitmap;
    bitmap.allocN32Pixels(BitmapSize, BitmapSize);
    SkCanvas canvas(bitmap);
    canvas.clear(0x00000000);

    auto flattenable = SkImageFilter::Deserialize(data, size);

    if (flattenable != nullptr) {
        // Let's see if using the filters can cause any trouble...
        SkPaint paint;
        paint.setImageFilter(flattenable);
        canvas.save();
        canvas.clipRect(SkRect::MakeXYWH(
            0, 0, SkIntToScalar(BitmapSize), SkIntToScalar(BitmapSize)));

        // This call shouldn't crash or cause ASAN to flag any memory issues
        // If nothing bad happens within this call, everything is fine
        canvas.drawBitmap(bitmap, 0, 0, &paint);

        canvas.restore();
    }
    return 0;  // Non-zero return values are reserved for future use.
}
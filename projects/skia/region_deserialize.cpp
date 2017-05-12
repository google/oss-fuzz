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
// TODO(kjlubick): Move this into Skia proper


#include "SkCanvas.h"
#include "SkPaint.h"
#include "SkRegion.h"
#include "SkSurface.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    SkRegion region;
    if (!region.readFromMemory(data, size)) {
        return 0;
    }
    region.computeRegionComplexity();
    region.isComplex();
    SkRegion r2;
    if (region == r2) {
        region.contains(0,0);
    } else {
        region.contains(1,1);
    }
    auto s = SkSurface::MakeRasterN32Premul(1024, 1024);
    s->getCanvas()->drawRegion(region, SkPaint());
    return 0;  // Non-zero return values are reserved for future use.
}

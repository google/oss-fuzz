// Copyright 2025 Google LLC
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

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "src/piex.h"
#include "src/piex_types.h"


class MemoryStream : public piex::StreamInterface {
public:
    MemoryStream(const uint8_t* data, size_t size)
      : data_(data), size_(size) {}

    piex::Error GetData(const size_t offset,
                  const size_t length,
                  uint8_t* data) override {
        if (offset + length > size_) {
            return piex::Error::kFail;
        }
        memcpy(data, data_ + offset, length);
        return piex::Error::kOk;
    }

private:
    const uint8_t* data_;
    size_t         size_;
};


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    MemoryStream stream(data, size);

    piex::PreviewImageData preview_image_data;
    piex::GetPreviewImageData(&stream, &preview_image_data);

    return 0;
}
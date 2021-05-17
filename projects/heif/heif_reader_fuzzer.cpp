/*
# Copyright 2021 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>

#include "heifreader.h"
#include "heifwriter.h"

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    char filename[256];
    sprintf(filename, "/tmp/libfuzzer.heic");

    FILE *fp = fopen(filename, "wb");
    if (!fp)
        return 0;
    fwrite(data, size, 1, fp);
    fclose(fp);

    auto* reader = HEIF::Reader::Create();
    
    if (reader->initialize(filename) != HEIF::ErrorCode::OK)
    {
        HEIF::Reader::Destroy(reader);
        std::remove(filename);
        return 0;
    }

    HEIF::FileInformation info;
    reader->getFileInformation(info);

    // Find the item ID
    HEIF::ImageId itemId;
    reader->getPrimaryItem(itemId);

    uint64_t memoryBufferSize = 1024 * 1024;
    auto* memoryBuffer        = new uint8_t[memoryBufferSize];
    reader->getItemDataWithDecoderParameters(itemId, memoryBuffer, memoryBufferSize);
    delete[] memoryBuffer;

    HEIF::Reader::Destroy(reader);
    std::remove(filename);
    return 0;
}

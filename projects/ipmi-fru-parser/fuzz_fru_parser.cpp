// Copyright 2026 Google LLC
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

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include <string>

#include "frup.hpp"
#include "fru_area.hpp"
#include "writefrudata.hpp"

using FruAreaVector = std::vector<std::unique_ptr<IPMIFruArea>>;

int ipmiValidateCommonHeader(const uint8_t* fruData, const size_t dataLen);
int ipmiPopulateFruAreas(uint8_t* fruData, const size_t dataLen,
                         FruAreaVector& fruAreaVec);
ipmi_fru_area_type getFruAreaType(uint8_t areaOffset);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < 8)
    {
        return 0;
    }

    // 1. Direct Fuzzing of raw FRU Area Parsing for all FRU area types
    IPMIFruInfo fruInfo = {};
    parse_fru_area(IPMI_FRU_AREA_INTERNAL_USE, data, size, fruInfo);
    parse_fru_area(IPMI_FRU_AREA_CHASSIS_INFO, data, size, fruInfo);
    parse_fru_area(IPMI_FRU_AREA_BOARD_INFO, data, size, fruInfo);
    parse_fru_area(IPMI_FRU_AREA_PRODUCT_INFO, data, size, fruInfo);
    parse_fru_area(IPMI_FRU_AREA_MULTI_RECORD, data, size, fruInfo);

    // 2. Fuzzing IPMI Common Header Validation and Area Extraction
    if (ipmiValidateCommonHeader(data, size) == 0)
    {
        FruAreaVector fruAreaVec;
        // Pre-populate fruAreaVec with expected areas as done in writefrudata
        for (uint8_t fruEntry = IPMI_FRU_INTERNAL_OFFSET;
             fruEntry < (sizeof(struct common_header) - 2); fruEntry++)
        {
            fruAreaVec.emplace_back(
                std::make_unique<IPMIFruArea>(0, getFruAreaType(fruEntry)));
        }

        // Test populating areas from fuzzed image buffer
        std::vector<uint8_t> fruBuffer(data, data + size);
        ipmiPopulateFruAreas(fruBuffer.data(), fruBuffer.size(), fruAreaVec);

        // Test each individual extracted area
        for (auto& area : fruAreaVec)
        {
            if (area->getLength() >= 8 && area->getData() != nullptr)
            {
                IPMIFruInfo areaInfo = {};
                parse_fru_area(area->getType(), area->getData(), area->getLength(), areaInfo);
            }
        }
    }

    return 0;
}

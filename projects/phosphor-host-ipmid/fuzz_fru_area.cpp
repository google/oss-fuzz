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

#include "ipmi_fru_info_area.hpp"

#include <cstdint>
#include <cstring>
#include <string>

// Helper: extract a length-prefixed string from fuzz data
static bool extractString(const uint8_t*& data, size_t& remaining,
                          std::string& out)
{
    if (remaining < 1)
    {
        return false;
    }
    uint8_t len = data[0] % 64; // Cap at 63 to keep things reasonable
    data++;
    remaining--;

    if (remaining < len)
    {
        len = static_cast<uint8_t>(remaining);
    }

    out.assign(reinterpret_cast<const char*>(data), len);
    data += len;
    remaining -= len;
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 3)
    {
        return 0;
    }

    // Use first byte to decide which sections to populate
    uint8_t sectionMask = data[0];
    data++;
    size--;

    ipmi::fru::FruInventoryData inventory;

    // Property keys used by the FRU builder
    const char* keys[] = {"Type",        "Model Number", "Serial Number",
                          "Manufacturer", "Mfg Date",    "Name",
                          "Part Number",  "Version"};

    // Chassis section
    if (sectionMask & 0x01)
    {
        ipmi::fru::PropertyMap props;
        for (const auto& key : keys)
        {
            std::string val;
            if (!extractString(data, size, val))
            {
                break;
            }
            if (!val.empty())
            {
                props[key] = val;
            }
        }
        if (!props.empty())
        {
            inventory["Chassis"] = props;
        }
    }

    // Board section
    if (sectionMask & 0x02)
    {
        ipmi::fru::PropertyMap props;
        for (const auto& key : keys)
        {
            std::string val;
            if (!extractString(data, size, val))
            {
                break;
            }
            if (!val.empty())
            {
                props[key] = val;
            }
        }
        if (!props.empty())
        {
            inventory["Board"] = props;
        }
    }

    // Product section
    if (sectionMask & 0x04)
    {
        ipmi::fru::PropertyMap props;
        for (const auto& key : keys)
        {
            std::string val;
            if (!extractString(data, size, val))
            {
                break;
            }
            if (!val.empty())
            {
                props[key] = val;
            }
        }
        if (!props.empty())
        {
            inventory["Product"] = props;
        }
    }

    if (!inventory.empty())
    {
        ipmi::fru::buildFruAreaData(inventory);
    }

    return 0;
}

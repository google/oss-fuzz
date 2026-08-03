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

#include "dbus-sdr/sensorutils.hpp"

#include <cstdint>
#include <cstring>
#include <stdexcept>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // We need 3 doubles (24 bytes) minimum
    if (size < 24)
    {
        return 0;
    }

    double max, min, value;
    std::memcpy(&max, data, sizeof(double));
    std::memcpy(&min, data + 8, sizeof(double));
    std::memcpy(&value, data + 16, sizeof(double));

    // Test getSensorAttributes
    int16_t mValue = 0;
    int8_t rExp = 0;
    int16_t bValue = 0;
    int8_t bExp = 0;
    bool bSigned = false;

    bool result =
        ipmi::getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned);

    // If getSensorAttributes succeeded, also test scaleIPMIValueFromDouble
    if (result && mValue != 0)
    {
        try
        {
            ipmi::scaleIPMIValueFromDouble(value, mValue, rExp, bValue, bExp,
                                           bSigned);
        }
        catch (const std::out_of_range&)
        {
            // Expected for mValue == 0, but we check above
        }
    }

    // Test getScaledIPMIValue directly
    try
    {
        ipmi::getScaledIPMIValue(value, max, min);
    }
    catch (const std::runtime_error&)
    {
        // Expected for invalid sensor attributes
    }
    catch (const std::out_of_range&)
    {
        // Expected for mValue == 0 conditions
    }

    return 0;
}

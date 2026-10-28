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
//
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <string>
#include <algorithm>
#include <cctype>

// Forward declaration of variable_field from libpldm
struct variable_field;

namespace pldm
{
namespace utils
{

inline std::string toString(const struct variable_field& var)
{
    // We will cast the struct pointers. In libpldm, variable_field is:
    // struct variable_field { const uint8_t* ptr; size_t length; }
    // We can access them via reinterpret_cast if needed, or since we include
    // libpldm headers in the fuzzer, the full definition will be available.
    
    // To be safe and compile without knowing the exact layout of variable_field here,
    // we can implement this in a .cpp file or just assume the definition is available
    // because this header is always included after libpldm headers.
    // In package_parser.cpp:
    // #include <libpldm/firmware_update.h> (defines variable_field)
    // #include <phosphor-logging/lg2.hpp>
    // So the definition is indeed available!
    
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(var.ptr);
    size_t length = var.length;

    if (ptr == nullptr || !length)
    {
        return "";
    }

    std::string str(reinterpret_cast<const char*>(ptr), length);
    std::replace_if(
        str.begin(), str.end(), [](const char& c) { return !std::isprint(c); }, ' ');
    return str;
}

} // namespace utils
} // namespace pldm

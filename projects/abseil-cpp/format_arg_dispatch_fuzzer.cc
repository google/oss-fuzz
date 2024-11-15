// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <string>
#include <limits>
#include "absl/strings/str_format.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider provider(data, size);
    std::string output;

    // Integers
    int int_val = provider.ConsumeIntegral<int>();
    unsigned int uint_val = provider.ConsumeIntegral<unsigned int>();
    int64_t int64_val = provider.ConsumeIntegral<int64_t>();
    uint64_t uint64_val = provider.ConsumeIntegral<uint64_t>();
    
    absl::StrFormat("%d%x%o%u%X%ld%lu", int_val, int_val, int_val, 
                    uint_val, uint_val, int64_val, uint64_val);
    
    absl::StrFormat("%d%d%u", std::numeric_limits<int>::max(),
                    std::numeric_limits<int>::min(),
                    std::numeric_limits<unsigned int>::max());

    // Floating point
    double double_val = provider.ConsumeFloatingPoint<double>();
    absl::StrFormat("%f%e%g", double_val, double_val, double_val);
    
    static const double special_vals[] = {
        std::numeric_limits<double>::infinity(),
        -std::numeric_limits<double>::infinity(),
        std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::denorm_min(),
        std::numeric_limits<double>::min(),
        std::numeric_limits<double>::max()
    };
    for (double val : special_vals) {
        absl::StrFormat("%f%e%g", val, val, val);
    }

    // Bool and char
    bool bool_val = provider.ConsumeBool();
    char char_val = provider.ConsumeIntegral<char>();
    absl::StrFormat("%d%v%c", bool_val, bool_val, char_val);
    
    static const char special_chars[] = {
        '\0', '\n', '\t', '\r', '\\', '\'', '\"', '\x1F'
    };
    for (char c : special_chars) {
        absl::StrFormat("%c", c);
    }

    // Strings and format flags
    std::string str = provider.ConsumeRandomLengthString();
    absl::StrFormat("%s%10s%-10s", str.c_str(), str.c_str(), str.c_str());
    absl::StrFormat("%s", "");

    // Format flags, width and precision
    absl::StrFormat("%+d% d%-10d%010d%#x", int_val, int_val, int_val, int_val, int_val);
    absl::StrFormat("%10.5f%.10f%15.10f", double_val, double_val, double_val);

    return 0;
}

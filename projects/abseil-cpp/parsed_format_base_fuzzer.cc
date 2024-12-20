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

#include "absl/strings/string_view.h"
#include "absl/strings/internal/str_format/arg.h"
#include "absl/strings/internal/str_format/extension.h"

using absl::str_format_internal::FormatConversionCharInternal;
using absl::str_format_internal::FormatConversionSpecImpl;
using absl::str_format_internal::FormatSinkImpl;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const char kFormatModifiers[] = {'+', '-', ' ', '#', '0'};
    static const char kFormatChars[] = {'d', 'i', 's', 'x', 'X', 'f', 'F', 'g', 'G', 'e', 'E', 'p', 'c'};
    static const char* kLengthMods[] = {"h", "hh", "l", "ll", "L", "z", "j", "t"};
    
    FuzzedDataProvider provider(data, size);
    
    std::string format;
    while (provider.remaining_bytes() > 0) {
        // Format specifier generation
        format += '%';
        
        // Positional args (1-9)$
        format += std::to_string(provider.ConsumeIntegralInRange<int>(1, 9));
        format += "$";
        
        // Random format flags
        format += provider.PickValueInArray(kFormatModifiers);
        
        // Width - either number or *
        format += provider.ConsumeBool() ? "*" : 
                 std::to_string(provider.ConsumeIntegralInRange<int>(1, 100));
        
        // Precision - .number or .*
        format += ".";
        format += provider.ConsumeBool() ? "*" : 
                 std::to_string(provider.ConsumeIntegralInRange<int>(0, 20));
        
        // Length modifier
        format += provider.PickValueInArray(kLengthMods);
        
        // Final conversion char
        format += provider.PickValueInArray(kFormatChars);
    }

    // Test format parsing
    absl::string_view format_view(format);
    FormatConversionSpecImpl spec;
    spec.set_conversion_char(FormatConversionCharInternal::c);
    std::string out;
    FormatSinkImpl sink(&out);
    
    return 0;
}

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
//
////////////////////////////////////////////////////////////////////////////////

#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include "absl/strings/str_format.h"
#include "absl/strings/internal/str_format/arg.h"
#include "absl/strings/internal/str_format/bind.h"

using absl::str_format_internal::FormatArgImpl;
using absl::str_format_internal::UntypedFormatSpecImpl;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) return 0;
    
    FuzzedDataProvider provider(data, size);
    
    // Create a fixed-size array of test values
    std::vector<int> values;
    values.resize(5);
    for (int i = 0; i < 5; i++) {
        values[i] = provider.ConsumeIntegral<int>();
    }
    
    // Create FormatArgImpl array from test values
    std::vector<FormatArgImpl> args;
    for (const int& val : values) {
        args.push_back(FormatArgImpl(val));
    }

    // Test format strings that match the test patterns from FormatBindTest
    const char* format_strings[] = {
        "a%4db%dc",       // Basic width
        "a%.4db%dc",      // Basic precision
        "a%4.5db%dc",     // Width and precision
        "a%db%4.5dc",     // Mixed formats
        "a%db%*.*dc",     // Dynamic width/precision
        "a%.*fb",         // Float precision
        "a%1$db%2$*3$.*4$dc",  // Positional parameters
        "a%4$db%3$*2$.*1$dc",  // Reverse positional
        "a%04ldb",        // Zero padding
        "a%-#04lldb",     // All flags
        "a%1$*5$db",      // Positional width
        "a%1$.*5$db"      // Positional precision
    };

    // Pick a format string and summarize
    std::string fmt = provider.PickValueInArray(format_strings);
    UntypedFormatSpecImpl format(fmt);
    std::string result = absl::str_format_internal::Summarize(
        format, absl::MakeSpan(args));

    return 0;
}

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
#include <stddef.h>
#include <stdint.h>
#include <string>

#include "absl/strings/string_view.h"
#include "absl/strings/match.h"
#include "absl/strings/ascii.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;  // Need at least 2 bytes

    FuzzedDataProvider provider(data, size);
    
    // Get a random string for the haystack
    std::string haystack = provider.ConsumeRandomLengthString();
    
    // Get a single char to search for
    char needle = provider.ConsumeIntegral<char>();
    
    // Create string_view from the haystack string
    absl::string_view haystack_view(haystack);
    
    // Call the function under test
    absl::StrContainsIgnoreCase(haystack_view, needle);
    
    return 0;
}

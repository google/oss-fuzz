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
#include "absl/strings/numbers.h"
#include "absl/numeric/int128.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    
    FuzzedDataProvider provider(data, size);
    absl::int128 signed_value;
    absl::uint128 unsigned_value;
    
    // Test with generated input
    std::string test_input = provider.ConsumeRemainingBytesAsString();
    absl::numbers_internal::safe_strto128_base(test_input.c_str(), &signed_value, 10);
    absl::numbers_internal::safe_strtou128_base(test_input.c_str(), &unsigned_value, 10);

    return 0;
}

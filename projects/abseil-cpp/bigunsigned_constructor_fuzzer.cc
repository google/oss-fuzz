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
#include "absl/strings/internal/charconv_bigint.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider provider(data, size);
    
    // Test with decimal number
    std::string numeric_str(
        provider.ConsumeIntegralInRange<size_t>(1, 20),
        provider.PickValueInArray({'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'})
    );
    absl::strings_internal::BigUnsigned<4> numeric_num(numeric_str);
    numeric_num.ToString();
    
    // Test with maximum digits
    std::string max_str(absl::strings_internal::BigUnsigned<4>::Digits10(), '9');
    absl::strings_internal::BigUnsigned<4> max_num(max_str);
    max_num.ToString();
    
    // Test with mixed chars
    std::string mixed_str(
        provider.ConsumeIntegralInRange<size_t>(1, 20),
        provider.PickValueInArray({'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
                                 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'})
    );
    absl::strings_internal::BigUnsigned<4> mixed_num(mixed_str);
    mixed_num.ToString();
    
    // Test empty string
    absl::strings_internal::BigUnsigned<4> empty_num("");
    empty_num.ToString();
    
    // Test non-digit string
    std::string non_digit_str(
        provider.ConsumeIntegralInRange<size_t>(1, 20),
        provider.ConsumeIntegralInRange<char>('a', 'z')
    );
    absl::strings_internal::BigUnsigned<4> non_digit_num(non_digit_str);
    non_digit_num.ToString();

    return 0;
}

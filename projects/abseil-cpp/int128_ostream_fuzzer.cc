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
#include <stdint.h>
#include <sstream>
#include <string>
#include <ios>

#include "absl/numeric/int128.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const std::ios_base::fmtflags kFormatFlags[] = {
        std::ios_base::dec,
        std::ios_base::hex,
        std::ios_base::oct,
        std::ios_base::dec | std::ios_base::showbase,
        std::ios_base::hex | std::ios_base::showbase,
        std::ios_base::oct | std::ios_base::showbase,
        std::ios_base::dec | std::ios_base::showpos,
        std::ios_base::hex | std::ios_base::uppercase,
        std::ios_base::dec | std::ios_base::left,
        std::ios_base::dec | std::ios_base::right,
        std::ios_base::dec | std::ios_base::internal
    };
    
    FuzzedDataProvider provider(data, size);
    
    // Create int128 value
    int64_t high = provider.ConsumeIntegral<int64_t>();
    uint64_t low = provider.ConsumeIntegral<uint64_t>();
    absl::int128 value = absl::MakeInt128(high, low);
    
    // Test stream configurations
    for (const auto& flag : kFormatFlags) {
        std::ostringstream oss;
        oss.flags(flag);
        
        // Add width and fill character
        char fill = provider.ConsumeIntegral<char>();
        int width = provider.ConsumeIntegralInRange<int>(0, 50);
        oss.fill(fill);
        oss.width(width);
        
        // Stream the value
        oss << value;
        
        // Stream again to verify consistency
        std::ostringstream oss2;
        oss2.flags(oss.flags());
        oss2.fill(oss.fill());
        oss2.width(oss.width());
        oss2 << value;
    }
    
    return 0;
}

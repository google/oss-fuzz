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
#include <limits>
#include <string>
#include "absl/strings/str_format.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) return 0;
    FuzzedDataProvider provider(data, size);
    std::string result;

    // Test literal percent (was missing)
    result = absl::StrFormat("%%");

    // Test basic integer types with different formats and sizes
    int value = provider.ConsumeIntegral<int>();
    result = absl::StrFormat("%d", value);
    result = absl::StrFormat("%i", value);
    result = absl::StrFormat("%u", value);
    result = absl::StrFormat("%x", value);
    result = absl::StrFormat("%X", value);
    result = absl::StrFormat("%o", value);

    // Test integers with length modifiers
    result = absl::StrFormat("%hhd", value);
    result = absl::StrFormat("%hd", value);
    result = absl::StrFormat("%ld", value);
    result = absl::StrFormat("%lld", value);
    result = absl::StrFormat("%zd", value);
    result = absl::StrFormat("%jd", value);
    result = absl::StrFormat("%td", value);
    
    // Test different integer sizes
    int8_t i8 = provider.ConsumeIntegral<int8_t>();
    result = absl::StrFormat("%d", i8);
    
    int16_t i16 = provider.ConsumeIntegral<int16_t>();
    result = absl::StrFormat("%d", i16);
    
    int64_t i64 = provider.ConsumeIntegral<int64_t>();
    result = absl::StrFormat("%d", i64);
    
    uint64_t u64 = provider.ConsumeIntegral<uint64_t>();
    result = absl::StrFormat("%u", u64);
    
    // Test integer format flags
    result = absl::StrFormat("%+d", value);
    result = absl::StrFormat("% d", value);
    result = absl::StrFormat("%-8d", value);
    result = absl::StrFormat("%08d", value);
    result = absl::StrFormat("%#x", value);
    // Additional flag combinations (were missing)
    result = absl::StrFormat("%+#x", value);
    result = absl::StrFormat("% #x", value);
    result = absl::StrFormat("%-#x", value);

    // Test floating point formats
    double double_val = provider.ConsumeFloatingPoint<double>();
    result = absl::StrFormat("%f", double_val);
    result = absl::StrFormat("%e", double_val);
    result = absl::StrFormat("%g", double_val);
    result = absl::StrFormat("%E", double_val);
    result = absl::StrFormat("%G", double_val);
    result = absl::StrFormat("%.2f", double_val);
    result = absl::StrFormat("%10.2f", double_val);
    
    // Additional float tests (were missing)
    result = absl::StrFormat("%a", double_val);
    result = absl::StrFormat("%A", double_val);
    result = absl::StrFormat("%#f", double_val);

    // Test extreme width/precision (were missing)
    result = absl::StrFormat("%100d", value);
    result = absl::StrFormat("%.100d", value);
    result = absl::StrFormat("%100.100d", value);

    // Test string formats
    std::string str = provider.ConsumeRandomLengthString();
    result = absl::StrFormat("%s", str);
    result = absl::StrFormat("%10s", str);
    result = absl::StrFormat("%-10s", str);
    result = absl::StrFormat("%.5s", str);

    // Test invalid format combinations (were missing)
    result = absl::StrFormat("%+s", str);  // + with string
    result = absl::StrFormat("% p", &str); // space with pointer

    // Test pointer format
    void* ptr = reinterpret_cast<void*>(provider.ConsumeIntegral<uintptr_t>());
    result = absl::StrFormat("%p", ptr);

    // Test character format
    char c = provider.ConsumeIntegral<char>();
    result = absl::StrFormat("%c", c);

    // Test width and precision
    int width = provider.ConsumeIntegralInRange<int>(0, 100);
    int precision = provider.ConsumeIntegralInRange<int>(0, 20);
    result = absl::StrFormat("%*d", width, value);
    result = absl::StrFormat("%.*f", precision, double_val);
    result = absl::StrFormat("%*.*f", width, precision, double_val);

    // Test limit values
    result = absl::StrFormat("%d", std::numeric_limits<int>::max());
    result = absl::StrFormat("%d", std::numeric_limits<int>::min());
    result = absl::StrFormat("%u", std::numeric_limits<unsigned int>::max());
    result = absl::StrFormat("%lld", std::numeric_limits<long long>::max());
    result = absl::StrFormat("%lld", std::numeric_limits<long long>::min());
    result = absl::StrFormat("%llu", std::numeric_limits<unsigned long long>::max());

    // Test special floating point values (were missing)
    double special_values[] = {
        std::numeric_limits<double>::infinity(),
        -std::numeric_limits<double>::infinity(),
        std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::denorm_min(),
        std::numeric_limits<double>::min(),
        std::numeric_limits<double>::max()
    };
    
    for (double d : special_values) {
        result = absl::StrFormat("%f", d);
        result = absl::StrFormat("%e", d);
        result = absl::StrFormat("%g", d);
        result = absl::StrFormat("%a", d);
    }

    // Test multiple argument formats
    result = absl::StrFormat("%d:%s:%g", value, str, double_val);
    result = absl::StrFormat("%x:%p:%.2f", value, ptr, double_val);
    result = absl::StrFormat("i=%d s='%s' f=%g", value, str, double_val);

    return 0;
}

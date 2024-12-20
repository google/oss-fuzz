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
#include <cstdint>
#include <string>
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"

// Test specific format strings that are compile-time constants
void TestFormat(int int_val, double double_val, const char* str_val, void* ptr_val) {
    std::string result;

    // Test integer formats
    result = absl::StrFormat("%d", int_val);
    result = absl::StrFormat("%x", int_val);
    result = absl::StrFormat("%04d", int_val);
    result = absl::StrFormat("%-5d", int_val);
    
    // Test float formats
    result = absl::StrFormat("%f", double_val);
    result = absl::StrFormat("%.2f", double_val);
    result = absl::StrFormat("%10.4f", double_val);
    result = absl::StrFormat("%e", double_val);
    
    // Test string formats
    result = absl::StrFormat("%s", str_val);
    result = absl::StrFormat("%10s", str_val);
    result = absl::StrFormat("%-10s", str_val);
    
    // Test pointer format
    result = absl::StrFormat("%p", ptr_val);
    
    // Test combined formats
    result = absl::StrFormat("int=%d str=%s float=%.2f ptr=%p", 
                            int_val, str_val, double_val, ptr_val);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) return 0;
    
    FuzzedDataProvider provider(data, size);
    
    // Generate test values
    int int_val = provider.ConsumeIntegral<int>();
    double double_val = provider.ConsumeFloatingPoint<double>();
    std::string str_val = provider.ConsumeRandomLengthString();
    void* ptr_val = reinterpret_cast<void*>(provider.ConsumeIntegral<uintptr_t>());
    
    TestFormat(int_val, double_val, str_val.c_str(), ptr_val);
    
    return 0;
}

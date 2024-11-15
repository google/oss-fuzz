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
    if (size < 4) return 0;
    
    FuzzedDataProvider provider(data, size);
    wchar_t test_value = provider.ConsumeIntegral<wchar_t>();
    
    std::string out;
    FormatSinkImpl sink(&out);
    
    FormatConversionSpecImpl conv;
    conv.set_conversion_char(FormatConversionCharInternal::c);
    
    absl::str_format_internal::FormatConvertImpl(test_value, conv, &sink);

    return 0;
}

// Copyright 2020 Google Inc.
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


#include "absl/crc/crc32c.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>

#include "absl/crc/internal/crc32c.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 10)
    {
        return 0;
    }
    uint32_t base = (uint32_t)*data;
    std::string str (reinterpret_cast<const char*>(data), size);
    std::string str2 (reinterpret_cast<const char*>(data), size);
    absl::ExtendCrc32c(absl::crc32c_t{base}, str2),
    absl::ExtendCrc32cByZeroes(absl::crc32c_t{base}, size);
    absl::crc32c_t crc_a = absl::ComputeCrc32c(str);
    absl::crc32c_t crc_b = absl::ComputeCrc32c(str);
    absl::ConcatCrc32c(crc_a, crc_b, str.size());
    absl::MemcpyCrc32c(&(str[0]), str2.data(), size);
    absl::crc_internal::UnextendCrc32cByZeroes(crc_a, size);
    
	return 0;
}
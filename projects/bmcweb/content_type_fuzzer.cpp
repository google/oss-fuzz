/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "http_utility.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0)
    {
        return 0;
    }

    std::string_view input(reinterpret_cast<const char*>(data), size);

    // Test content type parser
    http_helpers::getContentType(input);

    // Test preferred content type parser with various preference orders
    constexpr std::array<http_helpers::ContentType, 3> defaultPrefs = {
        http_helpers::ContentType::JSON, http_helpers::ContentType::HTML,
        http_helpers::ContentType::CBOR};
    http_helpers::getPreferredContentType(input, defaultPrefs);

    // Test content type allowed check
    http_helpers::isContentTypeAllowed(input, http_helpers::ContentType::JSON,
                                       true);
    http_helpers::isContentTypeAllowed(input, http_helpers::ContentType::JSON,
                                       false);

    // Test encoding parser
    constexpr std::array<http_helpers::Encoding, 3> defaultEncodings = {
        http_helpers::Encoding::ZSTD, http_helpers::Encoding::GZIP,
        http_helpers::Encoding::UnencodedBytes};
    http_helpers::getPreferredEncoding(input, defaultEncodings);

    return 0;
}

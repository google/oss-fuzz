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

#include "http_request.hpp"
#include "multipart_parser.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 4)
    {
        return 0;
    }

    // Use first two bytes to determine boundary length (1-64 chars)
    uint8_t boundaryLen =
        static_cast<uint8_t>((data[0] % 64) + 1); // 1-64 chars
    size_t offset = 1;

    if (offset + boundaryLen > size)
    {
        return 0;
    }

    std::string boundary(reinterpret_cast<const char*>(data + offset),
                         boundaryLen);
    offset += boundaryLen;

    std::string_view body(reinterpret_cast<const char*>(data + offset),
                          size - offset);

    std::error_code ec;
    crow::Request req(body, ec);

    std::string contentType = "multipart/form-data; boundary=";
    contentType += boundary;
    req.addHeader("Content-Type", contentType);

    MultipartParser parser;
    parser.parse(req);

    return 0;
}

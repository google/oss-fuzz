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

#include "json_html_serializer.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

// Reuse bmcweb's own SAX parser to limit depth/width
#include "http/parsing.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0)
    {
        return 0;
    }

    std::string input(reinterpret_cast<const char*>(data), size);

    // Parse JSON using bmcweb's own SAX parser (with depth/width limits)
    std::optional<nlohmann::json> parsed = parseStringAsJson(input);

    if (parsed)
    {
        // Exercise the HTML serializer on successfully parsed JSON
        std::string html;
        json_html_util::dumpHtml(html, *parsed);
        (void)html;
    }

    return 0;
}

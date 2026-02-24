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

#include "filter_expr_printer.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0)
    {
        return 0;
    }

    std::string_view input(reinterpret_cast<const char*>(data), size);

    // Use parseFilter which exercises phrase_parse (space-skipping) and
    // the FilterExpressionPrinter on successful parses
    std::optional<redfish::filter_ast::LogicalAnd> result =
        redfish::parseFilter(input);

    if (result)
    {
        // Exercise the AST printer on successfully parsed expressions
        redfish::FilterExpressionPrinter printer;
        std::string printed = printer(*result);
        (void)printed;
    }

    return 0;
}

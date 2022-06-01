// Copyright 2021 Google LLC
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

#include <string>

#include "parser/options.h"
#include "parser/parser.h"

#define MAX_RECURSION 0x100

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string str (reinterpret_cast<const char*>(data), size);
    google::api::expr::parser::ParserOptions options;
    options.max_recursion_depth = MAX_RECURSION;
    try {
        auto parse_status = google::api::expr::parser::Parse(str, "fuzzinput", options);
        if (!parse_status.ok()) {
            parse_status.status().message();
        }
    } catch (const std::exception& e) {
        return 0;
    }
    return 0;
}

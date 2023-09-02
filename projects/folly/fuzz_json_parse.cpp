/* Copyright 2021 Google LLC
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
#include <folly/json.h>
#include <folly/experimental/JSONSchema.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string input(reinterpret_cast<const char*>(data), size);
    try {
        auto val = folly::parseJson(input.c_str());
    }
    catch(...) {

    }
    try {
        folly::json::metadata_map map;
        folly::dynamic val = parseJsonWithMetadata(input.c_str(), &map);
        for (const auto& item : val) {
            auto v = folly::jsonschema::makeValidator(item["schema"]);
        }
    }
    catch(...) {}

    return 0;
}


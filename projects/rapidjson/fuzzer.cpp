/* Copyright 2024 Google LLC
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

#include <cstdint>
#include <cstddef>
#include <string>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>

#ifdef MSAN
extern "C" {
    void __msan_check_mem_is_initialized(const volatile void *x, size_t size);
}
#endif

template<unsigned parseFlags>
void fuzzWithFlags(const std::string &s) {
    rapidjson::Document document;
    rapidjson::ParseResult pr = document.Parse<parseFlags>(s.c_str());
    if (!pr) {
        return;
    }

    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);
    document.Accept(writer);
    std::string_view result(sb.GetString(), sb.GetSize());

#ifdef MSAN
    if (!result.empty()) {
        __msan_check_mem_is_initialized(result.data(), result.size());
    }
#endif
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Ensure the input is null-terminated by copying it into a std::string
    std::string s(reinterpret_cast<const char*>(data), size);

    fuzzWithFlags<rapidjson::kParseDefaultFlags>(s);
    fuzzWithFlags<rapidjson::kParseFullPrecisionFlag>(s);
    fuzzWithFlags<rapidjson::kParseNumbersAsStringsFlag>(s);
    fuzzWithFlags<rapidjson::kParseCommentsFlag>(s);

    return 0;
}

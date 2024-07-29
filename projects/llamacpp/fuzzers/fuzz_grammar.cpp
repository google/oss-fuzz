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

#include "grammar-parser.h"
#include "llama.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string payload(reinterpret_cast<const char *>(data), size);
  auto parsed_grammar = grammar_parser::parse(payload.c_str());
  if (parsed_grammar.rules.empty()) {
    return 0;
  }

  if (parsed_grammar.symbol_ids.find("root") !=
      parsed_grammar.symbol_ids.end()) {
    std::vector<const llama_grammar_element *> grammar_rules(
        parsed_grammar.c_rules());
    auto grammar = llama_grammar_init(grammar_rules.data(), grammar_rules.size(),
                       parsed_grammar.symbol_ids.at("root"));
    if (grammar != nullptr) {
      llama_grammar_free(grammar);
    }
  }
  return 0;
}

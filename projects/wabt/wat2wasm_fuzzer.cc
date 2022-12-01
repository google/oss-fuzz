// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "wabt/ir.h"
#include "wabt/wast-lexer.h"
#include "wabt/wast-parser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  wabt::Errors Lexerrors;
  std::unique_ptr<wabt::WastLexer> lexer =
      wabt::WastLexer::CreateBufferLexer("fake_file", data, size, &Lexerrors);

  if (!lexer) {
    return 0;
  }

  std::unique_ptr<wabt::Module> module;
  wabt::Errors errors;
  wabt::Features features;
  wabt::WastParseOptions parse_wast_options(features);
  ParseWatModule(lexer.get(), &module, &errors, &parse_wast_options);

  return 0;
}

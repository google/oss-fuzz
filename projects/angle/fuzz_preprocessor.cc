// Copyright 2026 Google LLC
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
//
////////////////////////////////////////////////////////////////////////////////

#include <fuzzer/FuzzedDataProvider.h>
#include <vector>

#include "compiler/preprocessor/Preprocessor.h"
#include "compiler/preprocessor/DiagnosticsBase.h"
#include "compiler/preprocessor/DirectiveHandlerBase.h"
#include "compiler/preprocessor/Token.h"

using namespace angle::pp;

namespace
{

class DoNothingDiagnostics : public Diagnostics
{
  public:
    void print(ID id, const SourceLocation &loc, const std::string &text) override {}
};

class DoNothingDirectiveHandler : public DirectiveHandler
{
  public:
    void handleError(const SourceLocation &loc, const std::string &msg) override {}
    void handlePragma(const SourceLocation &loc,
                      const std::string &name,
                      const std::string &value,
                      bool stdgl) override {}
    void handleExtension(const SourceLocation &loc,
                         const std::string &name,
                         const std::string &behavior) override {}
    void handleVersion(const SourceLocation &loc, int version, ShShaderSpec spec, MacroSet *macro_set) override {}
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;

    FuzzedDataProvider fuzzedData(data, size);

    ShShaderSpec spec = static_cast<ShShaderSpec>(fuzzedData.ConsumeIntegralInRange<int>(0, 5)); // SH_GLES3_2_SPEC is 5
    WebGLExtensionDisableBehavior behavior = fuzzedData.ConsumeBool() ? WebGLExtensionDisableBehavior::Standard : WebGLExtensionDisableBehavior::AnywhereInShader;

    PreprocessorSettings settings(spec, behavior);
    settings.maxMacroExpansionDepth = fuzzedData.ConsumeIntegralInRange<int>(0, 1000);

    DoNothingDiagnostics diagnostics;
    DoNothingDirectiveHandler directiveHandler;
    Preprocessor preprocessor(&diagnostics, &directiveHandler, settings);

    std::vector<uint8_t> remainingData = fuzzedData.ConsumeRemainingBytes<uint8_t>();
    if (remainingData.empty()) return 0;
    
    // Ensure null termination
    remainingData.push_back(0);

    const char *strings[] = { reinterpret_cast<const char *>(remainingData.data()) };
    if (!preprocessor.init(1, strings, nullptr))
    {
        return 0;
    }

    Token token;
    // Lex up to 1000 tokens to avoid infinite loops or very long execution
    for (int i = 0; i < 1000; ++i)
    {
        preprocessor.lex(&token);
        if (token.type == Token::LAST) break;
    }

    return 0;
}

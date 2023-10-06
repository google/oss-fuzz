/* Copyright 2023 Google LLC
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
#include "glslang/Public/ResourceLimits.h"
#include "glslang/Public/ShaderLang.h"
#include <string>


void compile(glslang::TShader *shader, const std::string &code,
             const std::string &entryPointName, EShMessages controls,
             const std::string *shaderName = nullptr) {
  const char *shaderStrings = code.data();
  const int shaderLengths = static_cast<int>(code.size());
  const char *shaderNames = nullptr;
  shader->setStringsWithLengths(&shaderStrings, &shaderLengths, 1);
  shader->setEntryPoint(entryPointName.c_str());
  shader->parse(GetDefaultResources(), 100, false, controls);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  glslang::InitializeProcess();
  std::string input_code(reinterpret_cast<const char *>(data), size);
  EShMessages controls;
  glslang::TShader shader(EShLangVertex);
  std::string shaderName = "shaderName";
  compile(&shader, input_code, "ep", controls, &shaderName);
  glslang::FinalizeProcess();
  return 0;
}

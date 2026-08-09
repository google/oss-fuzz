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


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  glslang::InitializeProcess();
  EShMessages controls;
  glslang::TShader shader(EShLangVertex);

  const char *dataPtr = (const char*)data;
  const int dataSize = (const int)size;

  shader.setStringsWithLengths(&dataPtr, &dataSize, 1);
  shader.setEntryPoint("ep");

  // Parse the shader
  shader.parse(GetDefaultResources(), 100, false, controls);

  glslang::FinalizeProcess();
  return 0;
}

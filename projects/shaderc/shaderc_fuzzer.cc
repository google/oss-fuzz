// Copyright 2024 Google LLC
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

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <shaderc/shaderc.h>
#include <shaderc/shaderc.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Skip iteration if data not enough
  if (size == 0) {
    return 0;
  }

  // Prepare GLSL shader content with valid version
  std::string shader_content(reinterpret_cast<const char *>(data), size);

  // Prepare Compiler and options
  shaderc::Compiler compiler;
  shaderc::CompileOptions options;
  options.SetOptimizationLevel(shaderc_optimization_level_performance);

  // Preprocessing
  shaderc::PreprocessedSourceCompilationResult preprocess_result =
      compiler.PreprocessGlsl(shader_content, shaderc_glsl_vertex_shader,
                              "input.glsl", options);
  if (preprocess_result.GetCompilationStatus() ==
      shaderc_compilation_status_success) {
    std::string preprocessed_code(preprocess_result.cbegin(),
                                  preprocess_result.cend());
  } else {
    return 0;
  }

  // Compile to SPIR-V binary
  shaderc::SpvCompilationResult binary_result = compiler.CompileGlslToSpv(
      shader_content, shaderc_glsl_vertex_shader, "input.glsl", options);
  if (binary_result.GetCompilationStatus() ==
      shaderc_compilation_status_success) {
    std::vector<uint32_t> spirv_binary(binary_result.cbegin(),
                                       binary_result.cend());
  }

  // Compile to SPIR-V assembly
  shaderc::AssemblyCompilationResult assembly_result =
      compiler.CompileGlslToSpvAssembly(
          shader_content, shaderc_glsl_vertex_shader, "input.glsl", options);
  if (assembly_result.GetCompilationStatus() ==
      shaderc_compilation_status_success) {
    std::string spirv_assembly(assembly_result.cbegin(),
                               assembly_result.cend());
  }

  // Compile with C API
  shaderc_compiler_t c_compiler = shaderc_compiler_initialize();
  shaderc_compilation_result_t c_result = shaderc_compile_into_spv(
      c_compiler, shader_content.c_str(), shader_content.size(),
      shaderc_glsl_vertex_shader, "main.vert", "main", nullptr);

  if (shaderc_result_get_compilation_status(c_result) ==
      shaderc_compilation_status_success) {
    std::vector<uint32_t> spirv_c_binary(shaderc_result_get_length(c_result) /
                                         sizeof(uint32_t));
    std::memcpy(spirv_c_binary.data(), shaderc_result_get_bytes(c_result),
                shaderc_result_get_length(c_result));
  }
  shaderc_result_release(c_result);
  shaderc_compiler_release(c_compiler);

  return 0;
}

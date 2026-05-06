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

#include <fuzzer/FuzzedDataProvider.h>

#include <shaderc/shaderc.h>
#include <shaderc/shaderc.hpp>

const std::array<shaderc_optimization_level, 3> OptArray = {
    shaderc_optimization_level_zero,
    shaderc_optimization_level_size,
    shaderc_optimization_level_performance,
};

const std::array<shaderc_shader_kind, 44> KindArray = {
    shaderc_vertex_shader,
    shaderc_fragment_shader,
    shaderc_compute_shader,
    shaderc_geometry_shader,
    shaderc_tess_control_shader,
    shaderc_tess_evaluation_shader,

    shaderc_glsl_vertex_shader,
    shaderc_glsl_fragment_shader,
    shaderc_glsl_compute_shader,
    shaderc_glsl_geometry_shader,
    shaderc_glsl_tess_control_shader,
    shaderc_glsl_tess_evaluation_shader,

    shaderc_glsl_infer_from_source,
    shaderc_glsl_default_vertex_shader,
    shaderc_glsl_default_fragment_shader,
    shaderc_glsl_default_compute_shader,
    shaderc_glsl_default_geometry_shader,
    shaderc_glsl_default_tess_control_shader,
    shaderc_glsl_default_tess_evaluation_shader,
    shaderc_spirv_assembly,
    shaderc_raygen_shader,
    shaderc_anyhit_shader,
    shaderc_closesthit_shader,
    shaderc_miss_shader,
    shaderc_intersection_shader,
    shaderc_callable_shader,

    shaderc_glsl_raygen_shader,
    shaderc_glsl_anyhit_shader,
    shaderc_glsl_closesthit_shader,
    shaderc_glsl_miss_shader,

    shaderc_glsl_intersection_shader,
    shaderc_glsl_callable_shader,
    shaderc_glsl_default_raygen_shader,
    shaderc_glsl_default_anyhit_shader,
    shaderc_glsl_default_closesthit_shader,
    shaderc_glsl_default_miss_shader,
    shaderc_glsl_default_intersection_shader,
    shaderc_glsl_default_callable_shader,
    shaderc_task_shader,
    shaderc_mesh_shader,
    shaderc_glsl_task_shader,
    shaderc_glsl_mesh_shader,
    shaderc_glsl_default_task_shader,
    shaderc_glsl_default_mesh_shader,
};

const std::array<shaderc_source_language, 2> LangArray = {
    shaderc_source_language_glsl,
    shaderc_source_language_hlsl,
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Prepare GLSL shader content with valid version
  shaderc_shader_kind kind = fdp.PickValueInArray(KindArray);

  // Prepare Compiler and options
  shaderc::Compiler compiler;
  shaderc::CompileOptions options;
  options.SetOptimizationLevel(fdp.PickValueInArray(OptArray));

  options.SetHlslFunctionality1(fdp.ConsumeBool());
  options.SetHlsl16BitTypes(fdp.ConsumeBool());
  options.SetInvertY(fdp.ConsumeBool());
  options.SetNanClamp(fdp.ConsumeBool());
  options.SetPreserveBindings(fdp.ConsumeBool());
  options.SetAutoMapLocations(fdp.ConsumeBool());
  options.SetHlslOffsets(fdp.ConsumeBool());
  options.SetAutoBindUniforms(fdp.ConsumeBool());
  options.SetSourceLanguage(fdp.PickValueInArray(LangArray));

  // Get the actual content
  std::string shader_content = fdp.ConsumeRandomLengthString();

  // Preprocessing
  shaderc::PreprocessedSourceCompilationResult preprocess_result =
      compiler.PreprocessGlsl(shader_content, kind, "input.glsl", options);
  if (preprocess_result.GetCompilationStatus() ==
      shaderc_compilation_status_success) {
    std::string preprocessed_code(preprocess_result.cbegin(),
                                  preprocess_result.cend());
  } else {
    return 0;
  }

  // Compile to SPIR-V binary
  shaderc::SpvCompilationResult binary_result =
      compiler.CompileGlslToSpv(shader_content, kind, "input.glsl", options);
  if (binary_result.GetCompilationStatus() ==
      shaderc_compilation_status_success) {
    std::vector<uint32_t> spirv_binary(binary_result.cbegin(),
                                       binary_result.cend());
  }

  // Compile to SPIR-V assembly
  shaderc::AssemblyCompilationResult assembly_result =
      compiler.CompileGlslToSpvAssembly(shader_content, kind, "input.glsl",
                                        options);
  if (assembly_result.GetCompilationStatus() ==
      shaderc_compilation_status_success) {
    std::string spirv_assembly(assembly_result.cbegin(),
                               assembly_result.cend());
  }

  // Compile with C API
  shaderc_compiler_t c_compiler = shaderc_compiler_initialize();
  shaderc_compilation_result_t c_result = shaderc_compile_into_spv(
      c_compiler, shader_content.c_str(), shader_content.size(), kind,
      "main.vert", "main", nullptr);

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

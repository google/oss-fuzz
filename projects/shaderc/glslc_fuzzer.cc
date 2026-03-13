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

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include "file_compiler.h"
#include <shaderc/shaderc.hpp>

namespace fs = std::filesystem;

std::string CreateTemporaryGLSLFile(const std::string &shader_content) {
  std::string temp_dir = fs::temp_directory_path().string();
  std::string temp_file =
      temp_dir + "/temp_shader_" + std::to_string(rand()) + ".glsl";
  std::ofstream ofs(temp_file);
  ofs << shader_content;
  ofs.close();
  return temp_file;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Create temporary glsl file with valid structure and fuzzed data
  // std::string shader_content = GenerateShaderContent(data, size);
  std::string payload(reinterpret_cast<const char *>(data), size);
  std::string temp_shader_file = CreateTemporaryGLSLFile(payload);

  // Initialize FileCompiler and options
  glslc::FileCompiler file_compiler;
  file_compiler.options().SetSuppressWarnings();
  file_compiler.AddIncludeDirectory(fs::temp_directory_path().string());
  file_compiler.SetOutputFileName("-");

  file_compiler.SetSpirvBinaryOutputFormat(
      glslc::FileCompiler::SpirvBinaryEmissionFormat::WGSL);

  glslc::InputFileSpec input_spec = {temp_shader_file,
                                     shaderc_glsl_fragment_shader,
                                     shaderc_source_language_glsl, "main"};

  // Fuzz common CompileShaderFile
  file_compiler.CompileShaderFile(input_spec);

  // Fuzz Preprocessing
  file_compiler.SetPreprocessingOnlyFlag();
  file_compiler.ValidateOptions(1);
  file_compiler.CompileShaderFile(input_spec);

  // Fuzz CompileShaderFile with DisassemblyFlag
  file_compiler.SetDisassemblyFlag();
  file_compiler.CompileShaderFile(input_spec);

  // Cleanup the temporary file
  fs::remove(temp_shader_file);

  return 0;
}

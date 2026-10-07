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

#include "spirv_common.hpp"
#include "spirv_parser.hpp"
#include <cstdint>
#include <vector>

using namespace spirv_cross;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Skip this iteration if data is not enough
  if (size < (sizeof(uint32_t) * 5) || (size % 4 != 0)) {
    return 0;
  }

  // Initialise objects and random data
  std::vector<uint32_t> spirv_data((uint32_t *)data, (uint32_t *)(data + size));

  // Set magic number, since this is needed to get past initial checks.
  spirv_data[0] = 0x07230203;
  spirv_data[1] = 0x10600;

  Parser parser(spirv_data);
  ParsedIR &ir = parser.get_parsed_ir();
  SPIRFunction *current_function = nullptr;
  SPIRBlock *current_block = nullptr;

  try {
    parser.parse();
  } catch (...) {
  }

  return 0;
}

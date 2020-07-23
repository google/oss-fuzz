// Copyright 2020 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "astcenc_internal.h"
#include "astcenccli_internal.h"
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {

  FuzzedDataProvider stream(data, size);
  astenc_profile decode_mode = stream.ConsumeEnum<astenc_profile>();
  unsigned int block_x = stream.ConsumeIntegral<unsigned int>();
  unsigned int block_y = stream.ConsumeIntegral<unsigned int>();
  unsigned int block_z = stream.ConsumeIntegral<unsigned int>();
  astenc_preset preset = stream.ConsumeEnum<astenc_preset>();
  std::vector<uint8_t> buffer = stream.ConsumeRemainingBytes<uint8_t>();

  astenc_config* config = nullptr;
  astcenc_error status = astcenc_config_init(
      decode_mode, block_x, block_y, block_z, preset, 0, config);

  if (status != ASTCENC_SUCCESS) return 0;

  block_size_descriptor* bsd = new block_size_descriptor;
	init_block_size_descriptor(block_x, block_y, block_z, bsd);

  uint8_t *out;

  decompress_symbolic_block(decode_mode, bsd, xpos, ypos, zpos, tempblocks + j, temp);

	return 0;
}

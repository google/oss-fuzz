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

unsigned int unpack_bytes(uint8_t a, uint8_t b, uint8_t c) {
  return ((unsigned int)a) + ((unsigned int)b << 8) + ((unsigned int)c << 16);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  if (size < 20)
    return 0;

  astc_compressed_image image_comp;
  astcenc_error error;
  astcenc_profile profile;
  int out_bitness;
  FuzzedDataProvider stream(data, size);

  const astcenc_profile profiles[] = {ASTCENC_PRF_LDR, ASTCENC_PRF_LDR_SRGB,
                                      ASTCENC_PRF_HDR,
                                      ASTCENC_PRF_HDR_RGB_LDR_A};

  int profile_type = stream.ConsumeIntegralInRange<int>(0, 3);
  profile = profiles[profile_type];
  out_bitness = 8 << (profile_type / 2);

  // Avoid dividing by zero
  uint8_t block_x = stream.ConsumeIntegral<uint8_t>();
  if (!block_x)
    block_x++;

  uint8_t block_y = stream.ConsumeIntegral<uint8_t>();
  if (!block_y)
    block_y++;

  uint8_t block_z = stream.ConsumeIntegral<uint8_t>();
  if (!block_z)
    block_z++;

  std::vector<uint8_t> dim_x_vector = stream.ConsumeBytes<uint8_t>(3);
  std::vector<uint8_t> dim_y_vector = stream.ConsumeBytes<uint8_t>(3);
  std::vector<uint8_t> dim_z_vector = stream.ConsumeBytes<uint8_t>(3);
  uint8_t *dim_x_data = dim_x_vector.data();
  uint8_t *dim_y_data = dim_y_vector.data();
  uint8_t *dim_z_data = dim_z_vector.data();

  // Dimensions cannot be zero
  unsigned int dim_x =
      unpack_bytes(*dim_x_data, *(dim_x_data + 1), *(dim_x_data + 2));
  if (!dim_x)
    dim_x++;

  unsigned int dim_y =
      unpack_bytes(*dim_y_data, *(dim_y_data + 1), *(dim_y_data + 2));
  if (!dim_x)
    dim_x++;

  unsigned int dim_z =
      unpack_bytes(*dim_z_data, *(dim_z_data + 1), *(dim_z_data + 2));
  if (!dim_x)
    dim_x++;

  unsigned int xblocks = (dim_x + block_x - 1) / block_x;
  unsigned int yblocks = (dim_y + block_y - 1) / block_y;
  unsigned int zblocks = (dim_z + block_z - 1) / block_z;
  unsigned int buffer_size = xblocks * yblocks * zblocks * 16;
  if (size - 20 < buffer_size)
    return 0;

  std::vector<uint8_t> buffer = stream.ConsumeBytes<uint8_t>(buffer_size);

  image_comp.data = buffer.data();
  image_comp.data_len = buffer.size();
  image_comp.block_x = block_x;
  image_comp.block_y = block_y;
  image_comp.block_z = block_z;
  image_comp.dim_x = dim_x;
  image_comp.dim_y = dim_y;
  image_comp.dim_z = dim_z;

  astcenc_config config{};
  astcenc_preset preset = ASTCENC_PRE_FAST;
  error = astcenc_config_init(profile, image_comp.block_x, image_comp.block_y,
                              image_comp.block_z, preset, 0, config);
  if (error)
    return 0;

  // Initialize cli_config_options with default values
  cli_config_options cli_config{
      0,
      1,
      false,
      false,
      -10,
      10,
      {ASTCENC_SWZ_R, ASTCENC_SWZ_G, ASTCENC_SWZ_B, ASTCENC_SWZ_A},
      {ASTCENC_SWZ_R, ASTCENC_SWZ_G, ASTCENC_SWZ_B, ASTCENC_SWZ_A}};

  astcenc_context *codec_context;
  error =
      astcenc_context_alloc(config, cli_config.thread_count, &codec_context);
  if (error)
    return 0;

  astcenc_image *image_decomp_out = alloc_image(
      out_bitness, image_comp.dim_x, image_comp.dim_y, image_comp.dim_z, 0);

  astcenc_decompress_image(codec_context, image_comp.data, image_comp.data_len,
                           *image_decomp_out, cli_config.swz_decode);

  return 0;
}

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
#include <limits>
#include <stdbool.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  if (size < 19)
    return 0;

  astc_compressed_image image_comp;
  astcenc_profile profile;
  int out_bitness;
  uint8_t uint8_max = std::numeric_limits<uint8_t>::max();
  FuzzedDataProvider stream(data, size);

  const astcenc_profile profiles[] = {ASTCENC_PRF_LDR, ASTCENC_PRF_LDR_SRGB,
                                      ASTCENC_PRF_HDR,
                                      ASTCENC_PRF_HDR_RGB_LDR_A};

  int profile_type = stream.ConsumeIntegralInRange<int>(0, 3);
  profile = profiles[profile_type];
  out_bitness = 8 << (profile_type / 2);

  // Avoid dividing by zero
  uint8_t block_x = stream.ConsumeIntegralInRange<uint8_t>(1, uint8_max);
  uint8_t block_y = stream.ConsumeIntegralInRange<uint8_t>(1, uint8_max);
  uint8_t block_z = stream.ConsumeIntegralInRange<uint8_t>(1, uint8_max);

  // Reference file consumes 3 bytes for each, so we define a maximum value
  unsigned int dim_x =
      stream.ConsumeIntegralInRange<uint32_t>(1, ~(0xff << 24));
  unsigned int dim_y =
      stream.ConsumeIntegralInRange<uint32_t>(1, ~(0xff << 24));
  unsigned int dim_z =
      stream.ConsumeIntegralInRange<uint32_t>(1, ~(0xff << 24));

  unsigned int xblocks = (dim_x + block_x - 1) / block_x;
  unsigned int yblocks = (dim_y + block_y - 1) / block_y;
  unsigned int zblocks = (dim_z + block_z - 1) / block_z;

  // Following the structure of
  // ARM-software/astc-encoder/Source/astcenccli_toplevel.cpp:main()
  size_t buffer_size = xblocks * yblocks * zblocks * 16;
  if (size - 19 < buffer_size)
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
  if (astcenc_config_init(profile, image_comp.block_x, image_comp.block_y,
                          image_comp.block_z, preset, 0,
                          config) != ASTCENC_SUCCESS)
    return 0;

  astcenc_swizzle default_swizzle{/*astcenc_swz r=*/ASTCENC_SWZ_R,
                                  /*astcenc_swz g=*/ASTCENC_SWZ_G,
                                  /*astcenc_swz b=*/ASTCENC_SWZ_B,
                                  /*astcenc_swz a=*/ASTCENC_SWZ_A};

  // Initialize cli_config_options with default values
  cli_config_options cli_config{/*unsigned int thread_count=*/0,
                                /*unsigned int array_size=*/1,
                                /*bool silent_mode=*/false,
                                /*bool y_flip=*/false,
                                /*int low_fstop=*/-10,
                                /*int high_fstop=*/10,
                                /*astcenc_swizzle swz_encode=*/default_swizzle,
                                /*astcenc_swizzle swz_decode=*/default_swizzle};

  astcenc_context *codec_context;
  if (astcenc_context_alloc(config, cli_config.thread_count, &codec_context) !=
      ASTCENC_SUCCESS)
    return 0;

  astcenc_image *image_decomp_out = alloc_image(
      out_bitness, image_comp.dim_x, image_comp.dim_y, image_comp.dim_z, 0);

  astcenc_decompress_image(codec_context, image_comp.data, image_comp.data_len,
                           *image_decomp_out, cli_config.swz_decode);

  return 0;
}

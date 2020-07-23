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

int init_astcenc_config(
	int argc,
	char **argv,
	astcenc_profile profile,
	astcenc_operation operation,
	astc_compressed_image& comp_image,
	astcenc_config& config
) {
	unsigned int block_x = 0;
	unsigned int block_y = 0;
	unsigned int block_z = 1;

	// For decode the block size is set by the incoming image.
	if (operation == ASTCENC_OP_DECOMPRESS)
	{
		block_x = comp_image.block_x;
		block_y = comp_image.block_y;
		block_z = comp_image.block_z;
	}

	astcenc_preset preset = ASTCENC_PRE_FAST;

	// parse the command line's encoding options.
	int argidx = 4;
	if (operation & ASTCENC_STAGE_COMPRESS)
	{
		// Read and decode block size
		if (argc < 5)
		{
			printf("ERROR: Block size must be specified\n");
			return 1;
		}

		int cnt2D, cnt3D;
		int dimensions = sscanf(argv[4], "%ux%u%nx%u%n",
		                        &block_x, &block_y, &cnt2D, &block_z, &cnt3D);
		// Character after the last match should be a NUL
		if (!(((dimensions == 2) && !argv[4][cnt2D]) || ((dimensions == 3) && !argv[4][cnt3D])))
		{
			printf("ERROR: Block size '%s' is invalid\n", argv[4]);
			return 1;
		}

		// Read and decode search preset
		if (argc < 6)
		{
			printf("ERROR: Search preset must be specified\n");
			return 1;
		}

		if (!strcmp(argv[5], "-fast"))
		{
			preset = ASTCENC_PRE_FAST;
		}
		else if (!strcmp(argv[5], "-medium"))
		{
			preset = ASTCENC_PRE_MEDIUM;
		}
		else if (!strcmp(argv[5], "-thorough"))
		{
			preset = ASTCENC_PRE_THOROUGH;
		}
		else if (!strcmp(argv[5], "-exhaustive"))
		{
			preset = ASTCENC_PRE_EXHAUSTIVE;
		}
		else
		{
			printf("ERROR: Search preset '%s' is invalid\n", argv[5]);
			return 1;
		}

		argidx = 6;
	}

	unsigned int flags = 0;

	// Gather the flags that we need
	while (argidx < argc)
	{
		if (!strcmp(argv[argidx], "-a"))
		{
			// Skip over the data value for now
			argidx++;
			flags |= ASTCENC_FLG_USE_ALPHA_WEIGHT;
		}
		else if (!strcmp(argv[argidx], "-normal"))
		{
			flags |= ASTCENC_FLG_MAP_NORMAL;
		}
		else if (!strcmp(argv[argidx], "-perceptual"))
		{
			flags |= ASTCENC_FLG_USE_PERCEPTUAL;
		}
		else if (!strcmp(argv[argidx], "-mask"))
		{

			flags |= ASTCENC_FLG_MAP_MASK;
		}
		argidx ++;
	}

#if defined(ASTCENC_DECOMPRESS_ONLY)
	flags |= ASTCENC_FLG_DECOMPRESS_ONLY;
#endif

	astcenc_error status = astcenc_config_init(profile, block_x, block_y, block_z, preset, flags, config);
	if (status == ASTCENC_ERR_BAD_BLOCK_SIZE)
	{
		printf("ERROR: Block size '%s' is invalid\n", argv[4]);
		return 1;
	}
	else if (status == ASTCENC_ERR_BAD_CPU_ISA)
	{
		printf("ERROR: Required SIMD ISA support missing on this CPU\n");
		return 1;
	}
	else if (status == ASTCENC_ERR_BAD_CPU_FLOAT)
	{
		printf("ERROR: astcenc must not be compiled with -ffast-math\n");
		return 1;
	}
	else if (status != ASTCENC_SUCCESS)
	{
		printf("ERROR: Init config failed with %s\n", astcenc_get_error_string(status));
		return 1;
	}

	return 0;
}

int edit_astcenc_config(
	int argc,
	char **argv,
	const astcenc_operation operation,
	cli_config_options& cli_config,
	astcenc_config& config
) {

	int argidx = 4;

	while (argidx < argc)
	{
		if (!strcmp(argv[argidx], "-va"))
		{
			argidx += 5;
			if (argidx > argc)
			{
				printf("ERROR: -va switch with less than 4 arguments\n");
				return 1;
			}

			config.v_a_power= static_cast<float>(atof(argv[argidx - 4]));
			config.v_a_base = static_cast<float>(atof(argv[argidx - 3]));
			config.v_a_mean = static_cast<float>(atof(argv[argidx - 2]));
			config.v_a_stdev = static_cast<float>(atof(argv[argidx - 1]));
		}
		else if (!strcmp(argv[argidx], "-cw"))
		{
			argidx += 5;
			if (argidx > argc)
			{
				printf("ERROR: -cw switch with less than 4 arguments\n");
				return 1;
			}

			config.cw_r_weight = static_cast<float>(atof(argv[argidx - 4]));
			config.cw_g_weight = static_cast<float>(atof(argv[argidx - 3]));
			config.cw_b_weight = static_cast<float>(atof(argv[argidx - 2]));
			config.cw_a_weight = static_cast<float>(atof(argv[argidx - 1]));
		}
		else if (!strcmp(argv[argidx], "-a"))
		{
			argidx += 2;
			if (argidx > argc)
			{
				printf("ERROR: -a switch with no argument\n");
				return 1;
			}

			config.a_scale_radius = atoi(argv[argidx - 1]);
		}
		else if (!strcmp(argv[argidx], "-b"))
		{
			argidx += 2;
			if (argidx > argc)
			{
				printf("ERROR: -b switch with no argument\n");
				return 1;
			}

			config.b_deblock_weight = static_cast<float>(atof(argv[argidx - 1]));
		}
		else if (!strcmp(argv[argidx], "-esw"))
		{
			argidx += 2;
			if (argidx > argc)
			{
				printf("ERROR: -esw switch with no argument\n");
				return 1;
			}

			if (strlen(argv[argidx - 1]) != 4)
			{
				printf("ERROR: -esw pattern does not contain 4 characters\n");
				return 1;
			}

			astcenc_swz swizzle_components[4];
			for (int i = 0; i < 4; i++)
			{
				switch (argv[argidx - 1][i])
				{
				case 'r':
					swizzle_components[i] = ASTCENC_SWZ_R;
					break;
				case 'g':
					swizzle_components[i] = ASTCENC_SWZ_G;
					break;
				case 'b':
					swizzle_components[i] = ASTCENC_SWZ_B;
					break;
				case 'a':
					swizzle_components[i] = ASTCENC_SWZ_A;
					break;
				case '0':
					swizzle_components[i] = ASTCENC_SWZ_0;
					break;
				case '1':
					swizzle_components[i] = ASTCENC_SWZ_1;
					break;
				default:
					printf("ERROR: -esw channel '%c' is not valid\n", argv[argidx - 1][i]);
					return 1;
				}
			}

			cli_config.swz_encode.r = swizzle_components[0];
			cli_config.swz_encode.g = swizzle_components[1];
			cli_config.swz_encode.b = swizzle_components[2];
			cli_config.swz_encode.a = swizzle_components[3];
		}
		else if (!strcmp(argv[argidx], "-dsw"))
		{
			argidx += 2;
			if (argidx > argc)
			{
				printf("ERROR: -dsw switch with no argument\n");
				return 1;
			}

			if (strlen(argv[argidx - 1]) != 4)
			{
				printf("ERROR: -dsw switch does not contain 4 characters\n");
				return 1;
			}

			astcenc_swz swizzle_components[4];
			for (int i = 0; i < 4; i++)
			{
				switch (argv[argidx - 1][i])
				{
				case 'r':
					swizzle_components[i] = ASTCENC_SWZ_R;
					break;
				case 'g':
					swizzle_components[i] = ASTCENC_SWZ_G;
					break;
				case 'b':
					swizzle_components[i] = ASTCENC_SWZ_B;
					break;
				case 'a':
					swizzle_components[i] = ASTCENC_SWZ_A;
					break;
				case '0':
					swizzle_components[i] = ASTCENC_SWZ_0;
					break;
				case '1':
					swizzle_components[i] = ASTCENC_SWZ_1;
					break;
				case 'z':
					swizzle_components[i] =  ASTCENC_SWZ_Z;
					break;
				default:
					printf("ERROR: ERROR: -dsw channel '%c' is not valid\n", argv[argidx - 1][i]);
					return 1;
				}
			}

			cli_config.swz_decode.r = swizzle_components[0];
			cli_config.swz_decode.g = swizzle_components[1];
			cli_config.swz_decode.b = swizzle_components[2];
			cli_config.swz_decode.a = swizzle_components[3];
		}
		// presets begin here
		else if (!strcmp(argv[argidx], "-normal"))
		{
			argidx++;

			cli_config.swz_encode.r = ASTCENC_SWZ_R;
			cli_config.swz_encode.g = ASTCENC_SWZ_R;
			cli_config.swz_encode.b = ASTCENC_SWZ_R;
			cli_config.swz_encode.a = ASTCENC_SWZ_G;

			cli_config.swz_decode.r = ASTCENC_SWZ_R;
			cli_config.swz_decode.g = ASTCENC_SWZ_A;
			cli_config.swz_decode.b = ASTCENC_SWZ_Z;
			cli_config.swz_decode.a = ASTCENC_SWZ_1;
		}
		else if (!strcmp(argv[argidx], "-perceptual"))
		{
			argidx++;
		}
		else if (!strcmp(argv[argidx], "-mask"))
		{
			argidx++;
		}
		else if (!strcmp(argv[argidx], "-blockmodelimit"))
		{
			argidx += 2;
			if (argidx > argc)
			{
				printf("ERROR: -blockmodelimit switch with no argument\n");
				return 1;
			}

			config.tune_block_mode_limit = atoi(argv[argidx - 1]);
		}
		else if (!strcmp(argv[argidx], "-partitionlimit"))
		{
			argidx += 2;
			if (argidx > argc)
			{
				printf("ERROR: -partitionlimit switch with no argument\n");
				return 1;
			}

			config.tune_partition_limit = atoi(argv[argidx - 1]);
		}
		else if (!strcmp(argv[argidx], "-dblimit"))
		{
			argidx += 2;
			if (argidx > argc)
			{
				printf("ERROR: -dblimit switch with no argument\n");
				return 1;
			}

			if ((config.profile == ASTCENC_PRF_LDR) || (config.profile == ASTCENC_PRF_LDR_SRGB))
			{
				config.tune_db_limit = static_cast<float>(atof(argv[argidx - 1]));
			}
		}
		else if (!strcmp(argv[argidx], "-partitionearlylimit"))
		{
			argidx += 2;
			if (argidx > argc)
			{
				printf("ERROR: -partitionearlylimit switch with no argument\n");
				return 1;
			}

			config.tune_partition_early_out_limit = static_cast<float>(atof(argv[argidx - 1]));
		}
		else if (!strcmp(argv[argidx], "-planecorlimit"))
		{
			argidx += 2;
			if (argidx > argc)
			{
				printf("ERROR: -planecorlimit switch with no argument\n");
				return 1;
			}

			config.tune_two_plane_early_out_limit = static_cast<float>(atof(argv[argidx - 1]));
		}
		else if (!strcmp(argv[argidx], "-refinementlimit"))
		{
			argidx += 2;
			if (argidx > argc)
			{
				printf("ERROR: -refinementlimit switch with no argument\n");
				return 1;
			}

			config.tune_refinement_limit = atoi(argv[argidx - 1]);
		}
		else if (!strcmp(argv[argidx], "-j"))
		{
			argidx += 2;
			if (argidx > argc)
			{
				printf("ERROR: -j switch with no argument\n");
				return 1;
			}

			cli_config.thread_count = atoi(argv[argidx - 1]);
		}
		else if (!strcmp(argv[argidx], "-yflip"))
		{
			argidx++;
			cli_config.y_flip = 1;
		}
		else if (!strcmp(argv[argidx], "-mpsnr"))
		{
			argidx += 3;
			if (argidx > argc)
			{
				printf("ERROR: -mpsnr switch with less than 2 arguments\n");
				return 1;
			}

			cli_config.low_fstop = atoi(argv[argidx - 2]);
			cli_config.high_fstop = atoi(argv[argidx - 1]);
			if (cli_config.high_fstop < cli_config.low_fstop)
			{
				printf("ERROR: -mpsnr switch <low> is greater than the <high>\n");
				return 1;
			}
		}

	}

	if (cli_config.thread_count <= 0)
	{
		cli_config.thread_count = get_cpu_count();
	}

#if defined(ASTCENC_DECOMPRESS_ONLY)
	cli_config.thread_count = 1;
#endif

	return 0;
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {

  if (size < 16) return 0;

  astc_compressed_image image_comp;
  astcenc_error error;
  int argc;
  char **argv;
  FuzzedDataProvider stream(data, size);

  // Avoid dividing by zero
  uint8_t block_x = stream.ConsumeIntegral<uint8_t>();
  if (!block_x) block_x++;

	uint8_t block_y = stream.ConsumeIntegral<uint8_t>();
  if (!block_y) block_y++;

	uint8_t block_z = stream.ConsumeIntegral<uint8_t>();
  if (!block_z) block_z++;

  std::vector<uint8_t> dim_x_vector = stream.ConsumeBytes<uint8_t>(3);
  std::vector<uint8_t> dim_y_vector = stream.ConsumeBytes<uint8_t>(3);
  std::vector<uint8_t> dim_z_vector = stream.ConsumeBytes<uint8_t>(3);
	uint8_t* dim_x_data = dim_x_vector.data();
	uint8_t* dim_y_data = dim_y_vector.data();
	uint8_t* dim_z_data = dim_z_vector.data();

  // Dimensions cannot be zero
  unsigned int dim_x = unpack_bytes(*dim_x_data, *(dim_x_data+1), *(dim_x_data+2));
  if (!dim_x) dim_x++;

	unsigned int dim_y = unpack_bytes(*dim_y_data, *(dim_y_data+1), *(dim_y_data+2));
  if (!dim_x) dim_x++;

	unsigned int dim_z = unpack_bytes(*dim_z_data, *(dim_z_data+1), *(dim_z_data+2));
  if (!dim_x) dim_x++;

  unsigned int xblocks = (dim_x + block_x - 1) / block_x;
	unsigned int yblocks = (dim_y + block_y - 1) / block_y;
	unsigned int zblocks = (dim_z + block_z - 1) / block_z;
  unsigned int buffer_size = xblocks * yblocks * zblocks * 16;
  if (size - 16 < buffer_size) return 0;

  std::vector<uint8_t> buffer = stream.ConsumeBytes<uint8_t>(buffer_size);

  image_comp.data = buffer.data();
	image_comp.data_len = buffer.size();
	image_comp.block_x = block_x;
	image_comp.block_y = block_y;
	image_comp.block_z = block_z;
	image_comp.dim_x = dim_x;
	image_comp.dim_y = dim_y;
	image_comp.dim_z = dim_z;

  // NOTE: Everything above this line working as expected

  astcenc_profile profile = ASTCENC_PRF_LDR; // TODO: Make this an enum selection to test different profiles

  astcenc_config config {};
	error = init_astcenc_config(argc, argv, profile, 0, image_comp, config); // TODO: Ensure argc and argv are valid
	if (error) return 0;

  // Initialize cli_config_options with default values
	cli_config_options cli_config { 0, 1, false, false, -10, 10,
		{ ASTCENC_SWZ_R, ASTCENC_SWZ_G, ASTCENC_SWZ_B, ASTCENC_SWZ_A },
		{ ASTCENC_SWZ_R, ASTCENC_SWZ_G, ASTCENC_SWZ_B, ASTCENC_SWZ_A } };

	error = edit_astcenc_config(argc, argv, 0, cli_config, config); // TODO: Ensure argc and argv are valid
  if (error) return 0;

  astcenc_context* codec_context;
	error = astcenc_context_alloc(config, cli_config.thread_count, &codec_context);
  if (error) return 0;

  int out_bitness = 8; // TODO: Make this value correspond to profile
  if (out_bitness == -1) {
    bool is_hdr = (config.profile == ASTCENC_PRF_HDR) || (config.profile == ASTCENC_PRF_HDR_RGB_LDR_A);
    out_bitness = is_hdr ? 16 : 8;
  }

  astcenc_image* image_decomp_out = alloc_image(
      out_bitness, image_comp.dim_x, image_comp.dim_y, image_comp.dim_z, 0);

  error = astcenc_decompress_image(
      codec_context, image_comp.data, image_comp.data_len,
      *image_decomp_out, cli_config.swz_decode);
  // if (error) return 0;

	return 0;
}

/*
# Copyright 2019 The Chromium OS Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <base/gserrors.h>
#include <psi/iapi.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static const unsigned char *g_data;
static size_t g_size;

int fuzz_gs_device(
	const unsigned char *buf,
	size_t size,
	int color_scheme,
	const char *device_target,
	const char *output_file
);

#define min(x, y) ((x) < (y) ? (x) : (y))

static int gs_stdin(void *inst, char *buf, int len)
{
	size_t to_copy = min(len, g_size);
	to_copy = min(INT_MAX, to_copy);

	memcpy(buf, g_data, to_copy);

	g_data += to_copy;
	g_size -= to_copy;

	return to_copy;
}

static int gs_stdnull(void *inst, const char *buf, int len)
{
	/* Just discard everything. */
	return len;
}

int gs_to_raster_fuzz(
	const unsigned char *buf,
	size_t size,
	int color_scheme
)
{
	return fuzz_gs_device(buf, size, color_scheme, "cups", "/dev/null");
}

int fuzz_gs_device(
	const unsigned char *buf,
	size_t size,
	int color_scheme,
	const char *device_target,
	const char *output_file
)
{
	int ret;
	void *gs = NULL;
	char color_space[50];
	char gs_device[50];
	char gs_o[100];
	/*
	 * We are expecting color_scheme to be in the [0:62] interval.
	 * This corresponds to the color schemes defined here:
	 * https://github.com/ArtifexSoftware/ghostpdl/blob/8c97d5adce0040ac38a1fb4d7954499c65f582ff/cups/libs/cups/raster.h#L102
	 */
	sprintf(color_space, "-dcupsColorSpace=%d", color_scheme);
	sprintf(gs_device, "-sDEVICE=%s", device_target);
	sprintf(gs_o, "-sOutputFile=%s", output_file);
	/* Mostly stolen from cups-filters gstoraster. */
	char *args[] = {
		"gs",
		"-K1048576",
		"-r200x200",
		"-sBandListStorage=memory",
		"-dMaxBitmap=0",
		"-dBufferSpace=450k",
		"-dMediaPosition=1",
		color_space,
		"-dQUIET",
		"-dSAFER",
		"-dNOPAUSE",
		"-dBATCH",
		"-dNOINTERPOLATE",
		"-dNOMEDIAATTRS",
		"-sstdout=%%stderr",
		gs_o,
		gs_device,
		"-_",
	};
	int argc = sizeof(args) / sizeof(args[0]);

	/* Stash buffers globally, for gs_stdin(). */
	g_data = buf;
	g_size = size;

	ret = gsapi_new_instance(&gs, NULL);
	if (ret < 0) {
		fprintf(stderr, "gsapi_new_instance: error %d\n", ret);
		return ret;
	}

	gsapi_set_stdio(gs, gs_stdin, gs_stdnull, gs_stdnull);
	ret = gsapi_set_arg_encoding(gs, GS_ARG_ENCODING_UTF8);
	if (ret < 0) {
		fprintf(stderr, "gsapi_set_arg_encoding: error %d\n", ret);
		gsapi_delete_instance(gs);
		return ret;
	}

	ret = gsapi_init_with_args(gs, argc, args);
	if (ret && ret != gs_error_Quit)
		/* Just keep going, to cleanup. */
		fprintf(stderr, "gsapi_init_with_args: error %d\n", ret);

	ret = gsapi_exit(gs);
	if (ret < 0 && ret != gs_error_Quit) {
		fprintf(stderr, "gsapi_exit: error %d\n", ret);
		return ret;
	}

	gsapi_delete_instance(gs);

	return 0;
}

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

static int gs_to_raster_fuzz(const unsigned char *buf, size_t size)
{
	int ret;
	void *gs = NULL;

	/* Mostly stolen from cups-filters gstoraster. */
	char *args[] = {
		"gs",
		"-K1048576",
		"-r200x200",
		"-sBandListStorage=memory",
		"-dMaxBitmap=0",
		"-dBufferSpace=450k",
		"-dMediaPosition=1",
		"-dcupsColorSpace=1", /* RGB */
		"-dQUIET",
		"-dSAFER",
		"-dNOPAUSE",
		"-dBATCH",
		"-dNOINTERPOLATE",
		"-dNOMEDIAATTRS",
		"-sstdout=%%stderr",
		"-sOutputFile=/dev/null",
		"-sDEVICE=cups",
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	gs_to_raster_fuzz(data, size);
	return 0;
}

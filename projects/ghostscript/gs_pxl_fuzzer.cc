/* Copyright 2026 Google LLC
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

/*
 * Fuzzer for Ghostscript's PXL (PCL XL / PCL6) interpreter.
 *
 * PXL is a binary tagged protocol identified by the stream header
 * ") HP-PCL XL". We write fuzz data to a temp file with this header
 * prepended so ghostpdl's auto-detection routes it to the PXL
 * interpreter (confidence 100 in pxl_detect_language).
 */

#include <base/gserrors.h>
#include <psi/iapi.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int gs_stdnull(void *inst, const char *buf, int len)
{
	return len;
}

/* Minimal PXL stream header: binding=';2', protocol=';0', newline */
static const char pxl_header[] = ") HP-PCL XL;2;0\n";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size == 0)
		return 0;

	/* Write fuzz data to temp file with PXL header prefix */
	char infile[256];
	sprintf(infile, "/tmp/fuzz_pxl.%d", getpid());
	FILE *f = fopen(infile, "wb");
	if (!f)
		return 0;
	fwrite(pxl_header, 1, sizeof(pxl_header) - 1, f);
	fwrite(data, 1, size, f);
	fclose(f);

	void *gs = NULL;
	int ret = gsapi_new_instance(&gs, NULL);
	if (ret < 0) {
		unlink(infile);
		return 0;
	}

	gsapi_set_stdio(gs, NULL, gs_stdnull, gs_stdnull);
	gsapi_set_arg_encoding(gs, GS_ARG_ENCODING_UTF8);

	char *args[] = {
		(char *)"gpdl",
		(char *)"-dNOPAUSE",
		(char *)"-dBATCH",
		(char *)"-dQUIET",
		(char *)"-dSAFER",
		(char *)"-sDEVICE=nullpage",
		(char *)"-sOutputFile=/dev/null",
		(char *)"-r72x72",
		infile,
	};
	int argc = sizeof(args) / sizeof(args[0]);

	ret = gsapi_init_with_args(gs, argc, args);
	gsapi_exit(gs);
	gsapi_delete_instance(gs);

	unlink(infile);
	return 0;
}

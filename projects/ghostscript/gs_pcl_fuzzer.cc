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
 * Fuzzer for Ghostscript's PCL5 interpreter.
 *
 * PCL5 is a binary escape-sequence format used in printers. The ghostpdl
 * auto-detection recognizes PCL by ESC (0x1b) bytes in the input. We write
 * fuzz data to a temp file and pass it as a filename so that ghostpdl can
 * use seekable I/O and proper language auto-detection.
 *
 * We prepend ESC-E (PCL reset) to ensure the auto-detector routes the
 * input to the PCL interpreter (confidence 100 in pcl_detect_language).
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size == 0)
		return 0;

	/* Write fuzz data to temp file with ESC-E prefix */
	char infile[256];
	sprintf(infile, "/tmp/fuzz_pcl.%d", getpid());
	FILE *f = fopen(infile, "wb");
	if (!f)
		return 0;
	/* PCL reset: ensures pcl_detect_language returns 100 */
	fputc(0x1b, f);
	fputc('E', f);
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

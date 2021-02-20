/* Copyright 2021 Google LLC
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

#include <stdio.h>
#include <stdlib.h>

#include "libyang.h"

int LLVMFuzzerTestOneInput(const char *data, size_t size) {
	struct ly_ctx *ctx = NULL;

	char filename[256];
	sprintf(filename, "/tmp/libfuzzer.%d", getpid());

	FILE *fp = fopen(filename, "wb");
	if (!fp) {
		return 0;
	}
	fwrite(data, size, 1, fp);
	fclose(fp);

    ctx = ly_ctx_new(NULL, 0);
    if (!ctx) {
        //fprintf(stderr, "failed to create context.\n");
        return 0;
    }
	lyxml_parse_path(ctx, filename, LYS_IN_YANG);
	ly_ctx_clean(ctx, NULL);
    ly_ctx_destroy(ctx, NULL);

    unlink(filename);
	return 0;
}


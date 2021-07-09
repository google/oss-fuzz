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

#include "libbb.h"
#include "bb_archive.h"

const char *applet_name="213";

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *new_str = (char *)malloc(size+1);
	if (new_str == NULL){
			return 0;
	}
	memcpy(new_str, data, size);
	new_str[size] = '\0';

	md5_ctx_t ctx1;
	unsigned char final[17];

	md5_begin(&ctx1);
	md5_hash(&ctx1, data, size);
	md5_end(&ctx1, final);

	unsigned char alt_result[64];
	sha256_ctx_t ctx2;
	sha256_begin(&ctx2);
	sha256_hash(&ctx2, data, size);
	sha256_end(&ctx2, alt_result);

	unsigned char alt_result2[64];
	sha512_ctx_t ctx3;
	sha512_begin(&ctx3);
	sha512_hash(&ctx3, data, size);
	sha512_end(&ctx3, alt_result);

	unicode_strlen(new_str);
	unicode_strwidth(new_str);
	if (strlen(new_str) > 40) {
		struct tm ptm;
		parse_datestr(new_str, &ptm);
	}

	free(new_str);
	return 0;
}

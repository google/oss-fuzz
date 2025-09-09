/* Copyright 2024 Google LLC
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
###############################################################################*/

#include "libwebsockets.h"
#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, uint32_t size) {
	const char *prot = NULL;
	const char *ads = NULL;
	const char *path = NULL;
	char *input = NULL;
	int  port;

	if (size > 0) {
		if (!(input = (char *)malloc(size + 1)))
			return (0);
		memcpy(input, data, size);
		input[size] = '\0';
		lws_parse_uri(input, &prot, &ads, &port, &path);
		free(input);
	}

	return 0;
}

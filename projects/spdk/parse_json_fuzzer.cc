/*
# Copyright 2021 Google LLC
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

#include <stdlib.h>
#include "spdk/json.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *buf = (char *)malloc(size);
	if (buf == NULL) {
		return 0;
	}
	memcpy(buf, data, size);
	ssize_t rc = spdk_json_parse(buf, size, NULL, 0, NULL, 0);

	free(buf);
	return 0;
}


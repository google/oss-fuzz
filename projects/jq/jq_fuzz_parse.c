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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "jv.h"

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
	// Creat null-terminated string
	char *null_terminated = (char*)malloc(size+1);
	memcpy(null_terminated, (char*)data, size);
	null_terminated[size] = '\0';

	// Fuzzer entrypoint
	jv res = jv_parse(null_terminated);
	jv_free(res);

	// Free the null-terminated string
	free(null_terminated);

    return 0;
}

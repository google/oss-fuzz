/* Copyright 2024 Google LLC
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
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "url.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *buf;
	char *r;
	const char *pbuf;

	buf = malloc(size + 1);
	if (!buf)
		return 0;

	memcpy(buf, data, size);
	buf[size] = 0;

	// start fuzzing
	r = url_decode(buf);
	free(r);

	r = url_percent_decode(buf);
	free(r);

	pbuf = (const char*) buf;
	r = url_decode_parameter_name(&pbuf);
	free(r);

	pbuf = (const char*) buf;
	r = url_decode_parameter_value(&pbuf);
	free(r);

	// cleanup
	free(buf);

	return 0;
}
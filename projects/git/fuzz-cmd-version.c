/* Copyright 2022 Google LLC
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
#include "builtin.h"

int cmd_version(int argc, const char **argv, const char *prefix);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int path;
	int argc;
	char *argv[2];

	if (size <= 10)
	{
		return 0;
	}

	path = (*((int *)data)) % 2;
	data += 4;
	size -= 4;

	switch(path)
	{
		// Without option
		default: case 0:
			argv[0] = (char *) data;
			argc = 1;
			break;

		// With option
		case 1:
			argv[0] = (char *) data;
			argv[1] = "--build-options";
			argc = 2;
			break;
	}

	cmd_version(argc, (const char **)argv, (const char *)"");

	return 0;
}

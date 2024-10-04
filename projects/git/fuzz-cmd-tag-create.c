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
#define USE_THE_REPOSITORY_VARIABLE

#include <stddef.h>
#include <stdint.h>
#include "fuzz-cmd-base.h"
#include "git-compat-util.h"
#include "repository.h"
#include "builtin.h"

int cmd_init_db(int argc, const char **argv, const char *prefix);
int cmd_tag(int argc, const char **argv, const char *prefix);

static int initialized = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *argv[4];
	char *buf = NULL;

	if (size == 0)
		return 0;

	if (!initialized)
	{
		put_envs();
		create_templ_dir();
	}

	int tokenStart = 0;
	for (int i = 0; i < size; ++i)
	{
		if (data[i] == '\0')
			break;

		if (data[i] == ' ')
			return 0;

		if (!tokenStart && data[i] == '-')
			return 0;

		tokenStart = 1;
	}

	buf = malloc(size + 1);
	if (!buf)
		goto cleanup;

	memcpy(buf, data, size);
	buf[size] = 0;

	if (!initialized)
	{
		initialize_repository(the_repository);
		system("rm -rf ./.git");
		system("echo \"TEMP1TEMP1TEMP1TEMP1\" > ./TEMP_1");
		system("echo \"TEMP1TEMP1TEMP1TEMP1\" > ./TEMP_2");
		if (reset_git_folder())
			exit(1);
		initialized = 1;
	}

	argv[0] = "tag";
	argv[1] = buf;
	argv[2] = NULL;
	cmd_tag(2, (const char **)argv, (const char *)"");

	argv[0] = "tag";
	argv[1] = "-d";
	argv[2] = buf;
	argv[3] = NULL;
	cmd_tag(3, (const char **)argv, (const char *)"");

cleanup:
	free(buf);
	return 0;
}

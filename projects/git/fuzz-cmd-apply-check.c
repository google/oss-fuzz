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
#include <unistd.h>
#include "git-compat-util.h"
#include "repository.h"
#include "fuzz-cmd-base.h"

int cmd_init_db(int argc, const char **argv, const char *prefix);
int cmd_apply(int argc, const char **argv, const char *prefix);

static int initialized = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *argv[3];

	if (size < 1)
		return 0;

	if (!initialized)
	{
		put_envs();
		create_templ_dir();
	}

	initialize_repository(the_repository);

	if (!initialized)
	{
		argv[0] = "init";
		argv[1] = "--quiet";
		argv[2] = NULL;
		if (cmd_init_db(2, (const char **)argv, (const char *)""))
			exit(1);

		initialized = 1;
	}

	if (-1 == write(STDIN_FILENO, data, size))
		goto cleanup;

	argv[0] = "apply";
	argv[1] = "-check";
	argv[2] = NULL;
	cmd_apply(2, (const char **)argv, (const char *)"");

cleanup:
	repo_clear(the_repository);
	return 0;
}

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
int cmd_bundle_verify(int argc, const char **argv, const char *prefix);

static int initialized = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *argv[4];

	if (!initialized)
	{
		put_envs();
		create_templ_dir();
		initialized = 1;
	}

	initialize_repository(the_repository);

	argv[0] = "init";
	argv[1] = "--quiet";
	argv[2] = NULL;
	if (cmd_init_db(2, (const char **)argv, (const char *)""))
		exit(1);

	if (randomize_git_file("/tmp", "fuzz.bundle", data, size))
		goto cleanup;

	argv[0] = "bundle";
	argv[1] = "--quiet";
	argv[2] = "/tmp/fuzz.bundle";
	argv[3] = NULL;
	cmd_bundle_verify(3, (const char **)argv, (const char *)"");

cleanup:
	repo_clear(the_repository);
	return 0;
}

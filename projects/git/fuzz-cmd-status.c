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
#include "repository.h"
#include "fuzz-cmd-base.h"

int cmd_status(int argc, const char **argv, const char *prefix);

static int initialized = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int i;
	int no_of_commit;
	int max_commit_count;
	char *argv[2];

	/*
	 * End this round of fuzzing if the data is not large enough
	 */
	if (size <= (HASH_HEX_SIZE + INT_SIZE))
	{
		return 0;
	}

	if (!initialized)
	{
		put_envs();
		create_templ_dir();
		initialized = 1;
	}

	system("rm -rf ./.git");
	system("echo \"TEMP1TEMP1TEMP1TEMP1\" > ./TEMP_1");
	system("echo \"TEMP1TEMP1TEMP1TEMP1\" > ./TEMP_2");

	initialize_repository(the_repository);

	if (reset_git_folder())
	{
		repo_clear(the_repository);
		return 0;
	}

	/*
	 * Generate random commit
	 */
	max_commit_count = get_max_commit_count(size, 0, INT_SIZE);
	no_of_commit = (*((int *)data)) % max_commit_count + 1;
	data += 4;
	size -= 4;

	for (i = 0; i < no_of_commit; i++)
	{
		if(generate_commit(data, HASH_SIZE))
		{
			repo_clear(the_repository);
			return 0;
		}
		data += HASH_HEX_SIZE;
		size -= HASH_HEX_SIZE;
	}

	/*
	 * Calling target git command
	 */
	argv[0] = "status";
	argv[1] = "-v";
	cmd_status(2, (const char **)argv, (const char *)"");

	repo_clear(the_repository);
	return 0;
}

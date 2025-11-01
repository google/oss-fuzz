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
#define USE_THE_REPOSITORY_VARIABLE

#include "git-compat-util.h"
#include <ftw.h>
#include <unistd.h>
#include <sys/stat.h>
#include "config.h"
#include "builtin.h"
#include "repository.h"
#include "fuzz-cmd-base.h"

int cmd_diff(int argc, const char **argv, const char *prefix);
int cmd_diff_files(int argc, const char **argv, const char *prefix);
int cmd_diff_index(int argc, const char **argv, const char *prefix);
int cmd_diff_tree(int argc, const char **argv, const char *prefix);

void generateGitConfig(char *);

void generateGitConfig(char *target_dir)
{
  /*
	char *git_config ="[user]\n\temail = \"FUZZ@LOCALHOST\"\n\t"
				"name = \"FUZZ\"\n[color]\n\tui = auto\n"
				"[safe]\n\tdirecory = *\n";
	FILE *fp = fopen(target_dir, 0777);
	fwrite(git_config, sizeof(char), strlen(git_config), fp);
	fclose(fp);
  */
  creat(target_dir, 0777);
}

static int initialized = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int i;
	int no_of_commit;
	int max_commit_count;
	char *argv[6];

	/*
	 * End this round of fuzzing if the data is not large enough
	 */
	if (size <= (HASH_HEX_SIZE * 2 + INT_SIZE))
	{
		return 0;
	}

	if (!initialized)
	{
		put_envs();
		create_templ_dir();
		initialized = 1;
	}

	/*
	 * Cleanup if needed
	 */
	system("rm -rf ./.git");
	system("rm -rf ./TEMP-*");
	/* add initial files for git add */
	system("echo \"TEMP1TEMP1TEMP1TEMP1\" > ./TEMP_1");
	system("echo \"TEMP1TEMP1TEMP1TEMP1\" > ./TEMP_2");

	initialize_repository(the_repository);

	/*
	 *  Initialize the repository
	 */
	if (reset_git_folder())
	{
		repo_clear(the_repository);
		return 0;
	}

	/*
	 * Generate random commit
	 */
	max_commit_count = get_max_commit_count(size, 0, HASH_HEX_SIZE + INT_SIZE);
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

	argv[0] = "branch";
	argv[1] = "-f";
	argv[2] = "new_branch";
	argv[3] = NULL;
	if (cmd_branch(3, (const char **)argv, (const char *)"")) 
	{
		repo_clear(the_repository);
		return 0;
	}

	/*
	 * Generate random file for diff
	 */
	randomize_git_file(".", "TEMP_1", data, HASH_SIZE);
	data += (HASH_SIZE);
	size -= (HASH_SIZE);

	randomize_git_file(".", "TEMP_2", data, HASH_SIZE);
	data += (HASH_SIZE);
	size -= (HASH_SIZE);

	/*
	 * Calling git diff command
	 */
	argv[0] = "diff";
	argv[1] = NULL;
	cmd_diff(1, (const char **)argv, (const char *)"");

	argv[1] = "TEMP_1";
	argv[2] = NULL;
	cmd_diff(2, (const char **)argv, (const char *)"");

	argv[2] = "TEMP_2";
	argv[3] = NULL;
	cmd_diff(3, (const char **)argv, (const char *)"");

	argv[1] = "HEAD";
	argv[2] = NULL;
	cmd_diff(2, (const char **)argv, (const char *)"");

	argv[1] = "--cached";
	argv[2] = NULL;
	cmd_diff(2, (const char **)argv, (const char *)"");

	argv[1] = "--diff-filter=MRC";
	argv[2] = "HEAD";
	argv[3] = NULL;
	cmd_diff(3, (const char **)argv, (const char *)"");

	argv[1] = "--diff-filter=MRC";
	argv[2] = "HEAD";
	argv[3] = NULL;
	cmd_diff(3, (const char **)argv, (const char *)"");

	argv[1] = "-R";
	argv[2] = "HEAD";
	argv[3] = NULL;
	cmd_diff(3, (const char **)argv, (const char *)"");

	argv[1] = "master";
	argv[2] = "new_branch";
	argv[3] = NULL;
 	cmd_diff(3, (const char **)argv, (const char *)"");

	/*
	* Calling git diff-files command
	*/
	argv[0] = "diff-files";
	argv[1] = NULL;
	cmd_diff_files(1, (const char **)argv, (const char *)"");
	argv[1] = "TEMP_1";
	argv[2] = NULL;
	cmd_diff_files(2, (const char **)argv, (const char *)"");
	argv[2] = "TEMP_2";
	argv[3] = NULL;
	cmd_diff_files(3, (const char **)argv, (const char *)"");

	/*
	* Calling git diff-tree command
	*/
	argv[0] = "diff-tree";
	argv[1] = "master";
	argv[2] = "--";
	argv[3] = NULL;
	cmd_diff_tree(3, (const char **)argv, (const char *)"");
	argv[0] = "diff-tree";
	argv[1] = "master";
	argv[2] = "new_branch";
	argv[3] = "--";
	argv[4] = NULL;
	cmd_diff_tree(4, (const char **)argv, (const char *)"");

	/*
	* Calling git diff-index command
	*/
	argv[0] = "diff-index";
	argv[1] = "master";
	argv[2] = "--";
	argv[3] = NULL;
	cmd_diff_index(3, (const char **)argv, (const char *)"");
	argv[2] = "--";
	argv[3] = "TEMP_1";
	argv[4] = NULL;
	cmd_diff_index(4, (const char **)argv, (const char *)"");
	argv[2] = "--";
	argv[3] = "TEMP_1";
	argv[4] = "TEMP_4";
	argv[5] = NULL;
	cmd_diff_index(5, (const char **)argv, (const char *)"");

	repo_clear(the_repository);
	return 0;
}

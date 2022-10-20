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

int cmd_add(int argc, const char **argv, const char *prefix);
int cmd_branch(int argc, const char **argv, const char *prefix);
int cmd_commit(int argc, const char **argv, const char *prefix);
int cmd_config(int argc, const char **argv, const char *prefix);
int cmd_diff(int argc, const char **argv, const char *prefix);
int cmd_diff_files(int argc, const char **argv, const char *prefix);
int cmd_diff_index(int argc, const char **argv, const char *prefix);
int cmd_diff_tree(int argc, const char **argv, const char *prefix);
int cmd_ls_files(int argc, const char **argv, const char *prefix);
int cmd_ls_tree(int argc, const char **argv, const char *prefix);
int cmd_mv(int argc, const char **argv, const char *prefix);
int cmd_rerere(int argc, const char **argv, const char *prefix);
int cmd_status(int argc, const char **argv, const char *prefix);
int cmd_version(int argc, const char **argv, const char *prefix);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int i;
	int argc;
	int no_of_commit;
	int no_of_loop;
	int max_commit_count;
	char *argv[6];
	char *data_chunk;
	char *basedir = "./.git";
	git_command_t choice;
	struct strbuf name = STRBUF_INIT;

	/*
	 *  Determine number of loop to execute
	 */
	if (size <= 4)
	{
		return 0;
	}
	no_of_loop = abs((*((int *)data)) % 20);
	data += 4;
	size -= 4;

	/*
	 * End this round of fuzzing if the data is not large enough
	 */
	if (size <= (HASH_HEX_SIZE * 2 + HASH_SIZE * 3 + INT_SIZE * (no_of_loop + 1)))
	{
		return 0;
	}

	/*
	 *  Initialize the repository
	 */
	initialize_the_repository();
	if (repo_init(the_repository, basedir, "."))
	{
		return 0;
	}

	if (reset_git_folder())
	{
		repo_clear(the_repository);
		return 0;
	}

	/*
	 * Generate random commit
	 */
	max_commit_count = get_max_commit_count(size, 0, HASH_SIZE * 3 + INT_SIZE * (no_of_loop + 1));
	no_of_commit = abs((*((int *)data)) % max_commit_count) + 1;
	data += 4;
	size -= 4;

	data_chunk = xmallocz_gently(HASH_HEX_SIZE);

	if (!data_chunk)
	{
		repo_clear(the_repository);
		return 0;
	}

	for (i = 0; i < no_of_commit; i++)
	{
		memcpy(data_chunk, data, HASH_HEX_SIZE);
		generate_commit(data_chunk, HASH_SIZE);
		data += HASH_HEX_SIZE;
		size -= HASH_HEX_SIZE;
	}

	free(data_chunk);

	/*
	 *  Create branch
	 */
	argv[0] = "branch";
	argv[1] = "-f";
	argv[2] = "new_branch";
	argv[3] = NULL;
	cmd_branch(3, (const char **)argv, (const char *)"");

	/*
	 * Alter content of TEMP_1 and TEMP_2
	 */
	data_chunk = xmallocz_gently(HASH_SIZE * 2);
	memcpy(data_chunk, data, HASH_SIZE * 2);
	char *nameset[] = {"TEMP_1", "TEMP_2"};
	randomize_git_files(".", nameset, 2, data_chunk, HASH_SIZE * 2);
	data += (HASH_SIZE * 2);
	size -= (HASH_SIZE * 2);
	free(data_chunk);

	/*
	 * Generate random name for different usage
	 */
	data_chunk = xmallocz_gently(HASH_SIZE);
	memcpy(data_chunk, data, HASH_SIZE);
	strbuf_addf(&name, "name-%s-name", hash_to_hex((unsigned char *)data_chunk));
	data += HASH_SIZE;
	size -= HASH_SIZE;
	free(data_chunk);

	for (i = 0 ; i < no_of_loop; i++)
	{
		choice = (*((int *)data)) % GIT_COMMAND_COUNT;
		data += 4;
		size -= 4;

		switch(choice) {
			case GIT_STATUS: default:
				argv[0] = "status";
				argv[1] = "-v";
				argv[2] = NULL;
				cmd_status(2, (const char **)argv, (const char *)"");

				break;

			case GIT_ADD_COMMIT_PUSH:
				argv[0] = "add";
				argv[1]	= "-u";
				argv[2] = NULL;
				cmd_add(2, (const char **)argv, (const char *)"");

				argv[0] = "commit";
				argv[1] = "-m";
				argv[2] = "\"New Commit\"";
				argv[3] = NULL;
				cmd_commit(3, (const char **)argv, (const char *)"");

				break;

			case GIT_VERSION:
				argv[0] = "version";
				argv[1] = NULL;
				cmd_version(1, (const char **)argv, (const char *)"");

				argv[1] = "--build-options";
				argv[2] = NULL;
				cmd_version(2, (const char **)argv, (const char *)"");

				break;

			case GIT_CONFIG_RERERE:
				argv[0] = "config";
				argv[1] = "--global";
				argv[2] = "rerere.enabled";
				argv[3] = "true";
				argv[4] = NULL;
				cmd_config(4, (const char **)argv, (const char *)"");

				argv[0] = "rerere";
				argv[1] = NULL;
				cmd_rerere(1, (const char **)argv, (const char *)"");

				argv[1] = "clear";
				argv[2] = NULL;
				cmd_rerere(2, (const char **)argv, (const char *)"");

				argv[1] = "diff";
				cmd_rerere(2, (const char **)argv, (const char *)"");

				argv[1] = "remaining";
				cmd_rerere(2, (const char **)argv, (const char *)"");

				argv[1] = "status";
				cmd_rerere(2, (const char **)argv, (const char *)"");

				argv[1] = "gc";
				cmd_rerere(2, (const char **)argv, (const char *)"");

				break;

			case GIT_DIFF:
				switch(i % 9) {
					case 0: default:
						argv[0] = "diff";
						argv[1] = NULL;
						cmd_diff(1, (const char **)argv, (const char *)"");

						break;

					case 1:
						argv[1] = "TEMP_1";
						argv[2] = NULL;
						cmd_diff(2, (const char **)argv, (const char *)"");

						break;

					case 2:
						argv[2] = "TEMP_2";
						argv[3] = NULL;
						cmd_diff(3, (const char **)argv, (const char *)"");

						break;

					case 3:
						argv[1] = "HEAD";
						argv[2] = NULL;
						cmd_diff(2, (const char **)argv, (const char *)"");

						break;

					case 4:
						argv[1] = "--cached";
						argv[2] = NULL;
						cmd_diff(2, (const char **)argv, (const char *)"");

						break;

					case 5:
						argv[1] = "--diff-filter=MRC";
						argv[2] = "HEAD";
						argv[3] = NULL;
						cmd_diff(3, (const char **)argv, (const char *)"");

						break;

					case 6:
						argv[1] = "--diff-filter=MRC";
						argv[2] = "HEAD^";
						argv[3] = NULL;
						cmd_diff(3, (const char **)argv, (const char *)"");

						break;

					case 7:
						argv[1] = "-R";
						argv[2] = "HEAD";
						argv[3] = NULL;
						cmd_diff(3, (const char **)argv, (const char *)"");

						break;

					case 8:
						argv[1] = "master";
						argv[2] = "new_branch";
						argv[3] = NULL;
						cmd_diff(3, (const char **)argv, (const char *)"");

						break;
				}

				break;

			case GIT_DIFF_FILES:
				argv[0] = "diff-files";
				argv[1] = NULL;
				cmd_diff_files(1, (const char **)argv, (const char *)"");

				argv[1] = "TEMP_1";
				argv[2] = NULL;
				cmd_diff_files(2, (const char **)argv, (const char *)"");

				argv[2] = "TEMP_2";
				argv[3] = NULL;
				cmd_diff_files(3, (const char **)argv, (const char *)"");

				break;

			case GIT_DIFF_TREE:
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

				break;

			case GIT_DIFF_INDEX:
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
				argv[4] = "TEMP_2";
				argv[5] = NULL;
				cmd_diff_index(5, (const char **)argv, (const char *)"");

				break;

			case GIT_BRANCH:
				argv[0] = "branch";
				argv[1] = name.buf;
				argv[2] = NULL;
				cmd_branch(2, (const char **)argv, (const char *)"");

				argv[1] = "-d";
				argv[2] = name.buf;
				argv[3] = NULL;
				cmd_branch(3, (const char **)argv, (const char *)"");

				break;

			case GIT_MV:
				argv[0] = "mv";
				argv[1] = "-k";
				argv[2] = "TEMP_1";
				argv[3] = name.buf;
				argv[4] = NULL;
				cmd_mv(4, (const char **)argv, (const char *)"");

				argv[1] = "-k";
				argv[2] = name.buf;
				argv[3] = "TEMP_1";
				argv[4] = NULL;
				cmd_mv(4, (const char **)argv, (const char *)"");

				break;

			case GIT_LS_FILES:
				argv[0] = "ls-files";
				argv[1] = NULL;
				cmd_ls_files(1, (const char **)argv, (const char *)"");

				argv[1] = "TEMP";
				argv[2] = NULL;
				cmd_ls_files(2, (const char **)argv, (const char *)"");

				argv[1] = "-m";
				argv[2] = NULL;
				cmd_ls_files(2, (const char **)argv, (const char *)"");

				argv[1] = name.buf;
				argv[2] = NULL;
				cmd_ls_files(2, (const char **)argv, (const char *)"");

				break;

			case GIT_LS_TREE:
				argv[0] = "ls-tree";
				argv[1] = "master";
				argv[2] = NULL;
				cmd_ls_tree(2, (const char **)argv, (const char *)"");

				break;
		}
	}

	strbuf_release(&name);
	repo_clear(the_repository);

	return 0;
}

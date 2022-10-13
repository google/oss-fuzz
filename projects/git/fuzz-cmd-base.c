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
#include "cache.h"
#include "builtin.h"
#include "fuzz-cmd-base.h"


/*
 * This function is used to randomize the content of a file with the
 * random data. The random data normally come from the fuzzing engine
 * LibFuzzer in order to create randomization of the git file worktree
 * and possibly messing up of certain git config file to fuzz different
 * git command execution logic. Return -1 if it fails to create the file.
 */
int randomize_git_file(char *dir, char *name, char *data, int size)
{
	FILE *fp;
	int ret = 0;
	struct strbuf fname = STRBUF_INIT;

	strbuf_addf(&fname, "%s/%s", dir, name);

	fp = fopen(fname.buf, "wb");
	if (fp)
	{
		fwrite(data, 1, size, fp);
	}
	else
	{
		ret = -1;
	}

	fclose(fp);
	strbuf_release(&fname);

	return ret;
}

/*
 * This function is a variant of the above function which takes
 * a set of target files to be processed. These target file are
 * passing to the above function one by one for content rewrite.
 * The data is equally divided for each of the files, and the
 * remaining bytes (if not divisible) will be ignored.
 */
void randomize_git_files(char *dir, char *name_set[],
	int files_count, char *data, int size)
{
	int i;
	int data_size = size / files_count;
	char *data_chunk = xmallocz_gently(data_size);

	if (!data_chunk)
	{
		return;
	}

	for (i = 0; i < files_count; i++)
	{
		memcpy(data_chunk, data + (i * data_size), data_size);
		randomize_git_file(dir, name_set[i], data_chunk, data_size);
	}
	free(data_chunk);
}

/*
 * Instead of randomizing the content of existing files. This helper
 * function helps generate a temp file with random file name before
 * passing to the above functions to get randomized content for later
 * fuzzing of git command.
 */
void generate_random_file(char *data, int size)
{
	unsigned char *hash = xmallocz_gently(size);
	char *data_chunk = xmallocz_gently(size);
	struct strbuf fname = STRBUF_INIT;

	if (!hash || !data_chunk)
	{
		return;
	}

	memcpy(hash, data, size);
	memcpy(data_chunk, data + size, size);

	strbuf_addf(&fname, "TEMP-%s-TEMP", hash_to_hex(hash));
	randomize_git_file(".", fname.buf, data_chunk, size);

	free(hash);
	free(data_chunk);
	strbuf_release(&fname);
}

/*
 * This function provides a shorthand for generate commit in master
 * branch.
 */
int generate_commit(char *data, int size)
{
	return generate_commit_in_branch(data, size, "master");
}

/*
 * This function helps to generate random commit and build up a
 * worktree with randomization to provide a target for the fuzzing
 * of git command under specific branch.
 */
int generate_commit_in_branch(char *data, int size, char *branch_name)
{
	char *argv[4];
	char *data_chunk = xmallocz_gently(HASH_HEX_SIZE);

	if (!data_chunk)
	{
		return -1;
	}

	memcpy(data_chunk, data, size * 2);
	generate_random_file(data_chunk, size);

	free(data_chunk);

	argv[0] = "add";
	argv[1] = "TEMP-*-TEMP";
	argv[2] = NULL;
	if (cmd_add(2, (const char **)argv, (const char *)""))
	{
		return -1;
	}

	argv[0] = "commit";
	argv[1] = "-m\"New Commit\"";
	argv[2] = NULL;
	if (cmd_commit(2, (const char **)argv, (const char *)""))
	{
		return -2;

	}
  	return 0;
}

/*
 * In some cases, there maybe some fuzzing logic that will mess
 * up with the git repository and its configuration and settings.
 * This function integrates into the fuzzing processing and
 * reset the git repository into the default
 * base settings before each round of fuzzing.
 * Return 0 for success.
 */
int reset_git_folder(void)
{
	char *argv[6];
	argv[0] = "init";
	argv[1] = NULL;
	if (cmd_init_db(1, (const char **)argv, (const char *)""))
	{
		return -1;
	}

  /*
  printf("R2\n");
	argv[0] = "config";
	argv[1] = "--global";
	argv[2] = "user.name";
	argv[3] = "\"FUZZ\"";
	argv[4] = NULL;
	if (cmd_config(4, (const char **)argv, (const char *)""))
	{
		return -2;
	}

  printf("R3\n");
	argv[0] = "config";
	argv[1] = "--global";
	argv[2] = "user.email";
	argv[3] = "\"FUZZ@LOCALHOST\"";
	argv[4] = NULL;
	if (cmd_config(4, (const char **)argv, (const char *)""))
	{
		return -3;
	}

  printf("R4\n");
	argv[0] = "config";
	argv[1] = "--global";
	argv[2] = "safe.directory";
	argv[3] = "\"*\"";
	argv[4] = NULL;
	if (cmd_config(4, (const char **)argv, (const char *)""))
	{
		return -4;
	}
  */
	argv[0] = "add";
	argv[1] = "TEMP_1";
	argv[2] = "TEMP_2";
	argv[3] = NULL;
	if (cmd_add(3, (const char **)argv, (const char *)""))
	{
		return -5;
	}

	argv[0] = "commit";
	argv[1] = "-m\"First Commit\"";
	argv[2] = NULL;
	if (cmd_commit(2, (const char **)argv, (const char *)""))
	{
		return -6;
	}

	return 0;
}

/*
 * This helper function returns the maximum number of commit can
 * be generated by the provided random data without reusing the
 * data to increase randomization of the fuzzing target and allow
 * more path of fuzzing to be covered.
 */
int get_max_commit_count(int data_size, int git_files_count, int reserve_size)
{
	int count = (data_size - reserve_size  - git_files_count * HASH_SIZE) / (HASH_HEX_SIZE);

	if (count > 20)
	{
		count = 20;
	}

	return count;
}

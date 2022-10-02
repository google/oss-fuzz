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
#ifndef FUZZ_CMD_BASE_H
#define FUZZ_CMD_BASE_H

#define HASH_SIZE 20
#define HASH_HEX_SIZE 40
#define INT_SIZE 4
#define GIT_COMMAND_COUNT 12

typedef enum git_command {
	GIT_STATUS = 0,
	GIT_ADD_COMMIT_PUSH = 1,
	GIT_VERSION = 2,
	GIT_CONFIG_RERERE = 3,
	GIT_DIFF = 4,
	GIT_DIFF_FILES = 5,
	GIT_DIFF_TREE = 6,
	GIT_DIFF_INDEX = 7,
	GIT_BRANCH = 8,
	GIT_MV = 9,
	GIT_LS_FILES = 10,
	GIT_LS_TREE = 11
} git_command_t;


int randomize_git_file(char *dir, char *name, char *data, int size);
void randomize_git_files(char *dir, char *name_set[],
	int files_count, char *data, int size);
void generate_random_file(char *data, int size);
int generate_commit(char *data, int size);
int generate_commit_in_branch(char *data, int size, char *branch_name);
int reset_git_folder(void);
int get_max_commit_count(int data_size, int git_files_count, int reserve_size);

#endif

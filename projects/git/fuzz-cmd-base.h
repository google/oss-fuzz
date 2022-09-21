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

int randomize_git_file(char *dir, char *name, char *data, int size);
void randomize_git_files(char *dir, char *name_set[],
	int files_count, char *data, int size);
void generate_random_file(char *data, int size);
void generate_commit(char *data, int size);
void generate_commit_in_branch(char *data, int size, char *branch_name);
void reset_git_folder(void);
int get_max_commit_count(int data_size, int git_files_count, int hash_size);

#endif

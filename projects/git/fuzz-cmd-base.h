#ifndef FUZZ_CMD_BASE_H
#define FUZZ_CMD_BASE_H

#define HASH_SIZE 20

int randomize_git_file(char *dir, char *name, char *data, int size);
void randomize_git_files(char *dir, char *name_set[],
	int files_count, char *data, int size);
void generate_random_file(char *data, int size);
void generate_commit(char *data, int size);
void generate_commit_in_branch(char *data, int size, char *branch_name);
void reset_git_folder(void);
int get_max_commit_count(int data_size, int git_files_count, int hash_size);

#endif

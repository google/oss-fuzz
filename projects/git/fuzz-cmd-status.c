#include "builtin.h"
#include "repository.h"
#include "fuzz-cmd-base.h"

int cmd_status(int argc, const char **argv, const char *prefix);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int i;
	int no_of_commit;
	int max_commit_count;
	char *argv[2];
	char *data_chunk;
	char *basedir = "./.git";

	/*
	 *  Initialize the repository
	 */
	initialize_the_repository();

	/*
	 * End this round of fuzzing if the data is not large enough
	 */
	if (size <= (HASH_HEX_SIZE + 4))
	{
		repo_clear(the_repository);
		return 0;
	}

	reset_git_folder();

	/*
	 * Generate random commit
	 */
	max_commit_count = get_max_commit_count(size, 0, HASH_SIZE) - 1;
	no_of_commit = (*((int *)data)) % max_commit_count + 1;
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
	 * Final preparing of the repository settings
	 */
	repo_clear(the_repository);
	if (repo_init(the_repository, basedir, "."))
	{
		repo_clear(the_repository);
		return 0;
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

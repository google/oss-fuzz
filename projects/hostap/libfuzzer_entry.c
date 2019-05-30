#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef EXTRA_ARGS
#define EXTRA_ARGS
#endif

#define DUMMY_FILE_NAME "/invalid/path/do/not/use"

static size_t input_size = 0;
static char* input_data = NULL;
static int use_count = 0;

int fuzzer_main(int argc, char *argv[]);

char* get_fuzzer_input(const char* fname, size_t *size) {
	assert(!strcmp(fname, DUMMY_FILE_NAME));
	*size = input_size;
	++use_count;
	return input_data;
}

void free_fuzzer_input(char* ptr) {
	assert(ptr == input_data);
}

FILE* fopen_fuzzer_input(const char* fname, const char* mode) {
	assert(!strcmp(fname, DUMMY_FILE_NAME));
	++use_count;
	return fmemopen(input_data, input_size, mode);
}

// Entry point for libFuzzer fuzzer, that wraps main of a fuzzer compatible with
// AFL (where input is passed via a file).
//
// TODO: Ideally, should add native libFuzzer entry to project's fuzzer, as this
// approach has noticable performance implications.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	char* argv[] = {"fuzzer", EXTRA_ARGS DUMMY_FILE_NAME};
	input_size = size;
	input_data = (char*) data;

	fuzzer_main(sizeof(argv) / sizeof(char*), argv);

	if (use_count == 0) {
		printf("ERROR: input not used!\n");
	}
	return 0;
}

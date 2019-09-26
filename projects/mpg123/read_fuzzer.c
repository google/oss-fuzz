#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "mpg123.h"

static char* fuzzer_get_tmpfile(const uint8_t* data, size_t size) {
  char* filename_buffer = strdup("/tmp/generate_temporary_file.XXXXXX");
  if (!filename_buffer) {
    perror("Failed to allocate file name buffer.");
    abort();
  }
  const int file_descriptor = mkstemp(filename_buffer);
  if (file_descriptor < 0) {
    perror("Failed to make temporary file.");
    abort();
  }
  FILE* file = fdopen(file_descriptor, "wb");
  if (!file) {
    perror("Failed to open file descriptor.");
    close(file_descriptor);
    abort();
  }
  const size_t bytes_written = fwrite(data, sizeof(uint8_t), size, file);
  if (bytes_written < size) {
    close(file_descriptor);
    fprintf(stderr, "Failed to write all bytes to file (%zu out of %zu)",
            bytes_written, size);
    abort();
  }
  fclose(file);
  return filename_buffer;
}

static void fuzzer_release_tmpfile(char* filename) {
  if (unlink(filename) != 0) {
    perror("WARNING: Failed to delete temporary file.");
  }
  free(filename);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static bool initialized = false;
  if (!initialized) {
    mpg123_init();
    initialized = true;
  }
  char* filename = fuzzer_get_tmpfile(data, size);
  if (filename == NULL) {
    return 0;
  }

  size_t outmemorysize = size * 2;  // Guess based on the size of data.
  unsigned char* outmemory = (unsigned char*)malloc(outmemorysize);
  if (outmemory == NULL) {
    fuzzer_release_tmpfile(filename);
    return 0;
  }

  int error;
  mpg123_handle* handle = mpg123_new(NULL, &error);
  if (handle == NULL || mpg123_param(handle,
      MPG123_ADD_FLAGS, MPG123_QUIET, 0.) != MPG123_OK) {
    free(outmemory);
    fuzzer_release_tmpfile(filename);
    return 0;
  }

  if (mpg123_open(handle, filename) == MPG123_OK) {
    int read_error;
    do {
      size_t decoded_size;
      read_error = mpg123_read(handle, outmemory, outmemorysize, &decoded_size);
    } while (read_error == MPG123_OK && mpg123_tellframe(handle) <= 10000
          && mpg123_tell_stream(handle) <= 1<<20);
  }

  mpg123_close(handle);
  mpg123_delete(handle);
  free(outmemory);
  fuzzer_release_tmpfile(filename);
  return 0;
}

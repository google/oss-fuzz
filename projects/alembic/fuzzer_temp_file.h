// Copyright 2020 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Adapter utility from fuzzer input to a temporary file, for fuzzing APIs that
// require a file instead of an input buffer.

#ifndef FUZZER_TEMP_FILE_H_
#define FUZZER_TEMP_FILE_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Pure-C interface for creating and cleaning up temporary files.

static char *fuzzer_get_tmpfile(const uint8_t *data, size_t size) {
  char *filename_buffer = strdup("/tmp/generate_temporary_file.XXXXXX");
  if (!filename_buffer) {
    perror("Failed to allocate file name buffer.");
    abort();
  }
  const int file_descriptor = mkstemp(filename_buffer);
  if (file_descriptor < 0) {
    perror("Failed to make temporary file.");
    abort();
  }
  FILE *file = fdopen(file_descriptor, "wb");
  if (!file) {
    perror("Failed to open file descriptor.");
    close(file_descriptor);
    abort();
  }
  const size_t bytes_written = fwrite(data, sizeof(uint8_t), size, file);
  if (bytes_written != size) {
    fclose(file);
    fprintf(stderr, "Failed to write all bytes to file (%zu out of %zu)",
            bytes_written, size);
    abort();
  }
  fclose(file);
  return filename_buffer;
}

static void fuzzer_release_tmpfile(char *filename) {
  if (unlink(filename) != 0) {
    perror("WARNING: Failed to delete temporary file.");
  }
  free(filename);
}

// C++ RAII object for creating temporary files.

#ifdef __cplusplus
class FuzzerTemporaryFile {
public:
  FuzzerTemporaryFile(const uint8_t *data, size_t size)
      : filename_(fuzzer_get_tmpfile(data, size)) {}

  ~FuzzerTemporaryFile() { fuzzer_release_tmpfile(filename_); }

  const char *filename() const { return filename_; }

private:
  char *filename_;
};
#endif

#endif // FUZZER_TEMP_FILE_H_

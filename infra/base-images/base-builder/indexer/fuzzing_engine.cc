// Copyright 2025 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t n);

extern "C" __attribute__((weak)) int LLVMFuzzerInitialize(int* argc,
                                                          char*** argv);

// Projects can call LLVMFuzzerMutate, but should only do it from
// LLVMFuzzerCustomMutator, which should be called from the fuzzing engine (we
// don't need to).
extern "C" size_t LLVMFuzzerMutate([[maybe_unused]] uint8_t* Data,
                                   [[maybe_unused]] size_t Size,
                                   [[maybe_unused]] size_t MaxSize) {
  fprintf(stderr, "LLVMFuzzerMutate was called. This should never happen.\n");
  __builtin_trap();
}

int main(int argc, char* argv[]) {
  if (LLVMFuzzerInitialize) {
    LLVMFuzzerInitialize(&argc, &argv);
  }

  if (argc != 2) {
    // Special-case because curl invokes the fuzzer binaries without arguments
    // during make, and will fail if they don't return success.
    if (strstr(argv[0], "curl_fuzzer")) {
      fprintf(stderr, "Exiting early for curl_fuzzer\n");
      exit(EXIT_SUCCESS);
    }

    fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  int fd = open(argv[1], O_RDONLY);
  if (fd == -1) {
    perror("open");
    exit(EXIT_FAILURE);
  }

  struct stat st;
  if (fstat(fd, &st) == -1) {
    perror("stat");
    exit(EXIT_FAILURE);
  }

  size_t size = static_cast<size_t>(st.st_size);
  uint8_t* data = static_cast<uint8_t*>(malloc(size));
  if (!data) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }

  size_t bytes_read = 0;
  while (bytes_read < size) {
    ssize_t res = read(fd, data + bytes_read, size - bytes_read);
    if (res == -1) {
      perror("read");
      exit(EXIT_FAILURE);
    }
    if (res == 0) {
      fprintf(stderr, "Unexpected EOF.\n");
      exit(EXIT_FAILURE);
    }
    bytes_read += static_cast<size_t>(res);
  }
  close(fd);

  int res = LLVMFuzzerTestOneInput(data, size);
  free(data);

  return res;
}

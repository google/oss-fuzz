/*
 * Copyright 2025 Google LLC

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *      http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// This is copied into the OSS-Fuzz container image and compiled
// there as part of the instrumentation process.

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t n);

extern "C" __attribute__((weak)) int LLVMFuzzerInitialize(
    __attribute__((unused)) int* argc, __attribute__((unused)) char*** argv) {
  return 0;
}

// Projects can call LLVMFuzzerMutate, but should only do it from
// LLVMFuzzerCustomMutator, which should be called from the fuzzing engine (we
// don't need to).
extern "C" size_t LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize) {
  fprintf(stderr, "LLVMFuzzerMutate was called. This should never happen.\n");
  __builtin_trap();
}

int main(int argc, char* argv[]) {
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

  const off_t end_offset = lseek(fd, 0, SEEK_END);
  if (end_offset == static_cast<off_t>(-1)) {
    perror("lseek SEEK_END");
    exit(EXIT_FAILURE);
  }

  if (lseek(fd, 0, SEEK_SET) == -1) {
    perror("lseek SEEK_SET");
    exit(EXIT_FAILURE);
  }

  const size_t size = static_cast<size_t>(end_offset);

  void* mapping = mmap(nullptr, static_cast<size_t>(size),
                       PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  if (mapping == MAP_FAILED) {
    perror("mmap");
    exit(EXIT_FAILURE);
  }
  close(fd);

  LLVMFuzzerInitialize(&argc, &argv);
  int res = LLVMFuzzerTestOneInput(static_cast<uint8_t*>(mapping), size);

  munmap(mapping, size);
  return res;
}

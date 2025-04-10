// This file is copied into the OSS-Fuzz container image and compiled there as
// part of the instrumentation process.

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(uint8_t data[], size_t n);

__attribute__((weak)) int LLVMFuzzerInitialize(
    __attribute__((unused)) int* argc, __attribute__((unused)) char*** argv) {
  return 0;
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

  int res = LLVMFuzzerInitialize(&argc, &argv);
  if (res != 0) {
    return res;
  }

  res = LLVMFuzzerTestOneInput(static_cast<uint8_t*>(mapping), size);

  munmap(mapping, size);
  return res;
}

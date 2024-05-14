#include <unistd.h>
#include <iostream>
#include <fstream>
#define NANOSVG_IMPLEMENTATION
#include "nanosvg.h"

extern "C" char* buf_to_file(const char *buf, size_t size) {
  char *name = strdup("/dev/shm/fuzz-XXXXXX");
  int fd = mkstemp(name);
  if (fd < 0) {
    perror("open");
    exit(1);
  }
  size_t pos = 0;
  while (pos < size) {
    int nbytes = write(fd, &buf[pos], size - pos);
    if (nbytes <= 0) {
      perror("write");
      exit(1);
    }
    pos += nbytes;
  }
  if (close(fd) != 0) {
    perror("close");
    exit(1);
  }
  return name;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	char *file = buf_to_file((const char *)data, size);

	struct NSVGimage* image;
    image = nsvgParseFromFile(file, "px", 96);
    unlink(file);
    free(file);
	return 0;
}
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>

static const uint8_t* fuzz_ptr;
static const uint8_t* fuzz_input;
static size_t fuzz_size;

int stress_main(int argc, char** argv);

 int LLVMFuzzerInitialize(int* argc, char*** argv) {
   char* exe_path = (*argv)[0];
   char* dir = dirname(exe_path);
   // Assume data files are at the same location as executable.
   setenv("CHEWING_PATH", dir, 0);
   setenv("CHEWING_USER_PATH", dir, 0);
   return 0;
 }

int get_fuzz_input() {
  if (fuzz_ptr - fuzz_input >= fuzz_size)
    return EOF;
  return *fuzz_ptr++;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  fuzz_input = fuzz_ptr = data;
  fuzz_size = size;

  const char *stress_argv[] = {
    "./chewing_fuzzer",
    "-extra",
    "-loop", "1",
    NULL,
  };
  stress_main(4, (char**)stress_argv);
  return 0;
}

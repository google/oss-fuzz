#include <stdio.h>

#include "chewing_fuzzer_common.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  fuzz_input = fuzz_ptr = data;
  fuzz_size = size;

  const char* stress_argv[] = {
      "./chewing_fuzzer", "-loop", "1", NULL,
  };
  stress_main(sizeof(stress_argv) / sizeof(stress_argv[0]) - 1,
              (char**)stress_argv);
  return 0;
}

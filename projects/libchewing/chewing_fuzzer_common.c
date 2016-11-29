#include "chewing_fuzzer_common.h"

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>

static char userphrase_path[] = "/tmp/chewing_userphrase.db.XXXXXX";

int LLVMFuzzerInitialize(int* argc, char*** argv) {
  char* exe_path = (*argv)[0];
  char* dir = dirname(exe_path);
  // Assume data files are at the same location as executable.
  setenv("CHEWING_PATH", dir, 0);

  // Specify user db of this process. So we can run multiple fuzzers at the
  // same time.
  mktemp(userphrase_path);
  setenv("TEST_USERPHRASE_PATH", userphrase_path, 0);
  return 0;
}

int get_fuzz_input() {
  if (fuzz_ptr - fuzz_input >= fuzz_size)
    return EOF;
  return *fuzz_ptr++;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STRINGLIT(S) #S
#define STRINGIFY(S) STRINGLIT(S)

// Required for oss-fuzz to consider the binary a target.
static const char* magic = "LLVMFuzzerTestOneInput";

int main(int argc, char* argv[]) {
  if (getenv("LD_LIBRARY_PATH")) {
    // Shouldn't be set. Code can be changed to append if it ever is.
    perror("LD_LIBRARY_PATH unexpectedly set");
    exit(1);
  }
  if (setenv("LD_LIBRARY_PATH", STRINGIFY(LIB_PATH), 0)) {
    perror("Error setting LD_LIBRARY_PATH");
    exit(1);
  }

  if (setenv("MOZ_RUN_GTEST", "1", 1) || setenv("LIBFUZZER", "1", 1) ||
      setenv("FUZZER", STRINGIFY(FUZZ_TARGET), 1)) {
    perror("Error setting fuzzing variables");
    exit(1);
  }

  // Temporary (or permanent?) work-around for a bug in the fuzzing interface.
  // https://bugzilla.mozilla.org/show_bug.cgi?id=1466021#c9
  char* options = getenv("ASAN_OPTIONS");
  if (!options) {
    perror("ASAN_OPTIONS not set ?!");
    exit(1);
  }
  char append[] = ":detect_stack_use_after_return=0";
  char* new_options = (char*)malloc(strlen(options) + sizeof(append));
  memcpy(new_options, options, strlen(options));
  memcpy(new_options + strlen(options), append, sizeof(append));
  if (setenv("ASAN_OPTIONS", new_options, 1)) {
    perror("Error setting ASAN_OPTIONS");
    exit(1);
  }
  free(new_options);

  return execv(STRINGIFY(FIREFOX_BINARY), argv);
}

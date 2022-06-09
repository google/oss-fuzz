#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STRINGLIT(S) #S
#define STRINGIFY(S) STRINGLIT(S)

// Required for oss-fuzz to consider the binary a target.
static const char* magic __attribute__((used)) = "LLVMFuzzerTestOneInput";

int main(int argc, char* argv[]) {
  char path[PATH_MAX] = {0};

  // Handle (currently not used) relative binary path.
  if (**argv != '/') {
    if (!getcwd(path, PATH_MAX - 1)) {
      perror("getcwd");
      exit(1);
    }
    strcat(path, "/");
  }

  if (strlen(path) + strlen(*argv) + 40 >= PATH_MAX) {
    fprintf(stderr, "Path length would exceed PATH_MAX\n");
    exit(1);
  }

  strcat(path, *argv);
  char* solidus = strrchr(path, '/');
  *solidus = 0; // terminate path before last /

  char ld_path[PATH_MAX] = {0};
  strcpy(ld_path, path);
  strcat(ld_path, "/lib");

  // Expects LD_LIBRARY_PATH to also be set by oss-fuzz.
  setenv("LD_LIBRARY_PATH", ld_path, 0);
  setenv("HOME", "/tmp", 0);
  setenv("FUZZER", STRINGIFY(FUZZ_TARGET), 1);

  char* options = getenv("ASAN_OPTIONS");
  if (options) {
    char* ptr;
    char* new_options = strdup(options);

    // https://bugzilla.mozilla.org/1477846
    ptr = strstr(new_options, "detect_stack_use_after_return=1");
    if (ptr) ptr[30] = '0';

    // https://bugzilla.mozilla.org/1477844
    ptr = strstr(new_options, "detect_leaks=1");
    if (ptr) ptr[13] = '0';

    setenv("ASAN_OPTIONS", new_options, 1);
    free(new_options);
  }


  char js_path[PATH_MAX] = {0};
  strcpy(js_path, path);
  strcat(js_path, "/fuzz-tests");

  int ret = execv(js_path, argv);
  if (ret)
    perror("execv");
  return ret;
}


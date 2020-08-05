// Copyright 2020 Google LLC
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

  // Expects LD_LIBRARY_PATH to not also be set by oss-fuzz.
  setenv("LD_LIBRARY_PATH", ld_path, 0);
  setenv("HOME", "/tmp", 0);
  setenv("FUZZER", STRINGIFY(FUZZ_TARGET), 1);

  // ContentParentIPC
  char blacklist_path[PATH_MAX] = {0};
  strcpy(blacklist_path, path);
  strcat(blacklist_path, "/firefox/libfuzzer.content.blacklist.txt");
  setenv("MOZ_IPC_MESSAGE_FUZZ_BLACKLIST", blacklist_path, 1);

  // Temporary (or permanent?) work-arounds for fuzzing interface bugs.
  char* options = getenv("ASAN_OPTIONS");
  const char max_alloc_size_opt[] = ":max_allocation_size_mb=2049";
  if (options) {
    size_t optlen = strlen(options);
    char* new_options = malloc(optlen + sizeof(max_alloc_size_opt));

    memcpy(new_options, options, optlen);
    memcpy(new_options + optlen, max_alloc_size_opt, sizeof(max_alloc_size_opt));

    char* ptr;

    // https://bugzilla.mozilla.org/1477846
    ptr = strstr(new_options, "detect_stack_use_after_return=1");
    if (ptr) ptr[30] = '0';
    // https://bugzilla.mozilla.org/1477844
    ptr = strstr(new_options, "detect_leaks=1");
    if (ptr) ptr[13] = '0';
    setenv("ASAN_OPTIONS", new_options, 1);
    free(new_options);
  }

  char ff_path[PATH_MAX] = {0};
  strcpy(ff_path, path);
  strcat(ff_path, "/firefox/firefox");

  int ret = execv(ff_path, argv);
  if (ret)
    perror("execv");
  return ret;
}

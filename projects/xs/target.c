/*
 ********************************************************************************
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ********************************************************************************
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STRINGLIT(S) #S
#define STRINGIFY(S) STRINGLIT(S)

// Heavily inspired by firefox's wrapper located at
// https://github.com/google/oss-fuzz/blob/master/projects/firefox/target.c

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

  setenv("FUZZER", STRINGIFY(FUZZ_TARGET), 1);

  // Temporary (or permanent?) work-arounds for fuzzing interface bugs.
  char* options = getenv("ASAN_OPTIONS");
  if (options) {
    char* ptr;
    char* new_options = strdup(options);
    // ptr = strstr(new_options, "detect_stack_use_after_return=1");
    // if (ptr) ptr[30] = '0';
    ptr = strstr(new_options, "detect_leaks=1");
    if (ptr) ptr[13] = '0';
    setenv("ASAN_OPTIONS", new_options, 1);
    free(new_options);
  }

  char real_fuzz_bin[PATH_MAX] = {0};
  strcpy(real_fuzz_bin, path);
  strcat(real_fuzz_bin, "/real/");
  strcat(real_fuzz_bin, STRINGIFY(FUZZ_TARGET));
  fprintf(stderr, "Invoking %s with detect_leaks=0\n", real_fuzz_bin);

  int ret = execv(real_fuzz_bin, argv);
  if (ret)
    perror("execv");
  return ret;
}

// Copyright 2022 Google LLC.
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

#include <libgen.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <fcntl.h>

#include "fuzzer_temp_file.h"

#include <magic.h>

struct Environment {
  Environment(std::string data_dir) {
    magic = magic_open(MAGIC_COMPRESS|MAGIC_CONTINUE|MAGIC_NO_COMPRESS_FORK);
    std::string magic_path = data_dir + "/magic";
    if (magic_load(magic, magic_path.c_str())) {
      fprintf(stderr, "error loading magic file: %s\n", magic_error(magic));
      exit(1);
    }
  }

  magic_t magic;
};

static Environment* env;

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
  char* exe_path = (*argv)[0];
  // dirname() can modify its argument.
  char* exe_path_copy = strdup(exe_path);
  char* dir = dirname(exe_path_copy);
  env = new Environment(dir);
  free(exe_path_copy);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzerTemporaryFile ftf (data, size);
  int fd = open(ftf.filename(), O_RDONLY);
  magic_descriptor(env->magic, fd);
  close(fd);
  return 0;
}

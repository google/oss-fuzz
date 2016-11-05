// Copyright 2016 Google Inc.
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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <magic.h>

struct Environment {
  Environment() {
    magic = magic_open(MAGIC_NONE);
    if (magic_load(magic, "magic")) {
      fprintf(stderr, "error loading magic file: %s\n", magic_error(magic));
      exit(1);
    }
  }

  magic_t magic;
};

static Environment env;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1)
    return 0;
  magic_buffer(env.magic, data, size);
  return 0;
}

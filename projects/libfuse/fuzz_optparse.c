/* Copyright 2023 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#define FUSE_USE_VERSION 31

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fuse.h>
#include <stddef.h>

// To make some fuzz data operations easier.
#include "ada_fuzz_header.h"

static char *my_argv[10];

static struct options {
  const char *char_opt1;
  const char *char_opt2;
  int int_opt3;
} options;

#define OPTION(t, p)                                                           \
  { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
    OPTION("--char_opt1=%s", char_opt1), OPTION("--char_opt2=%s", char_opt2),
    OPTION("-i", int_opt3), OPTION("--intopt3", int_opt3), FUSE_OPT_END};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  af_safe_gb_init(data, size);
  char *opt1 = ada_safe_get_char_p();
  char *opt2 = ada_safe_get_char_p();

  for (int i = 0; i < 10; i++) {
    my_argv[i] = ada_safe_get_char_p();
  }
  struct fuse_args args = {10, my_argv, 0};

  options.char_opt1 = strdup(opt1);
  options.char_opt2 = strdup(opt2);
  options.int_opt3 = ada_safe_get_int();

  if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1) {
    free(options.char_opt1);
    free(options.char_opt2);
    af_safe_gb_cleanup();
    return 0;
  }
  free(options.char_opt1);
  free(options.char_opt2);

  fuse_opt_free_args(&args);

  af_safe_gb_cleanup();
  return 0;
}

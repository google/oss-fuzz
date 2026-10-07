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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "flexdef.h"
#include "options.h"
#include "scanopt.h"

char *my_argv[4];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 24) {
    return 0;
  }
  char *opt_fuzz = malloc(24);

  memcpy(opt_fuzz, data, 23);
  opt_fuzz[23] = 0;
  data += 23;
  size -= 23;

  char *new_str = (char *)malloc(size + 1);
  if (new_str == NULL) {
    return 0;
  }
  memcpy(new_str, data, size);
  new_str[size] = '\0';
  my_argv[0] = "/tmp/fuzz/";
  my_argv[1] = opt_fuzz;
  my_argv[2] = new_str;
  my_argv[3] = NULL;

  scanopt_t sopt;
  sopt = scanopt_init(flexopts, 3, my_argv, 0);
  if (!sopt) {
    free(new_str);
    free(opt_fuzz);
    return 0;
  }
  int optind;
  char *arg;
  scanopt(sopt, &arg, &optind);
  scanopt_destroy(sopt);

  free(new_str);
  free(opt_fuzz);
  return 0;
}

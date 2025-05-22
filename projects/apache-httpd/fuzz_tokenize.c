/* Copyright 2021 Google LLC
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
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "apr_strings.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  apr_pool_t *pool;
  apr_pool_initialize();
  if (apr_pool_create(&pool, NULL) != APR_SUCCESS) {
    abort();
  }

  char *arg_str = strndup((const char *)data, size);
  char **argv_out;
  apr_tokenize_to_argv(arg_str, &argv_out, pool);

  free(arg_str);
  apr_pool_destroy(pool);
  apr_pool_terminate();

  return 0;
}

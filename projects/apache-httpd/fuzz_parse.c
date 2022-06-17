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
#include "apr.h"
#include "apr_file_io.h"
#include "apr_poll.h"
#include "apr_portable.h"
#include "apr_proc_mutex.h"
#include "apr_signal.h"
#include "apr_strings.h"
#include "apr_thread_mutex.h"
#include "apr_thread_proc.h"

#define APR_WANT_STRFUNC
#include "apr_file_io.h"
#include "apr_fnmatch.h"
#include "apr_want.h"

#include "apr_poll.h"
#include "apr_want.h"

#include "ap_config.h"
#include "ap_expr.h"
#include "ap_listen.h"
#include "ap_provider.h"
#include "ap_regex.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *new_str = (char *)malloc(size + 1);
  if (new_str == NULL) {
    return 0;
  }
  memcpy(new_str, data, size);
  new_str[size] = '\0';

  apr_pool_initialize();
  apr_pool_t *v = NULL;
  apr_pool_create(&v, NULL);

  int only_ascii = 1;
  for (int i = 0; i < size; i++) {
    // Avoid unnessary exits because of non-ascii characters.
    if (new_str[i] < 0x01 || new_str[i] > 0x7f) {
      only_ascii = 0;
    }
    // Avoid forced exits beause of, e.g. unsupported characters or recursion
    // depth
    if (new_str[i] == 0x5c || new_str[i] == '{') {
      only_ascii = 0;
    }
  }

  // Now parse
  if (only_ascii) {
    ap_expr_info_t val;
    ap_expr_parse(v, v, &val, new_str, NULL);
  }

  apr_pool_terminate();
  free(new_str);
  return 0;
}

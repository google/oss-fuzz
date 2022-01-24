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

#include "apr_uri.h"

#include "ap_config.h"
#include "ap_expr.h"
#include "ap_listen.h"
#include "ap_provider.h"
#include "ap_regex.h"

#include "ada_fuzz_header.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  af_gb_init();
  const uint8_t *data2 = data;
  size_t size2 = size;

  // Get a NULL terminated string
  char *cstr = af_gb_get_null_terminated(&data2, &size2);

  // Fuzz URI routines
  if (cstr && apr_pool_initialize() == APR_SUCCESS) {
    apr_pool_t *pool = NULL;
    apr_pool_create(&pool, NULL);

    apr_uri_t tmp_uri;
    if (apr_uri_parse(pool, cstr, &tmp_uri) == APR_SUCCESS) {
      apr_uri_unparse(pool, &tmp_uri, 0);
    }
    apr_uri_parse_hostinfo(pool, cstr, &tmp_uri);

    // Cleanup
    apr_pool_terminate();
  }

  af_gb_cleanup();
  return 0;
}

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

#include "ada_fuzz_header.h"
#include "apreq_parser.h"

apr_status_t hookfunc(apreq_hook_t *hook, apreq_param_t *param,
                      apr_bucket_brigade *bb) {
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  af_gb_init();

  const uint8_t *data2 = data;
  size_t size2 = size;

  /* get random data for the fuzzer */
  char *new_str = af_gb_get_null_terminated(&data2, &size2);
  char *new_str2 = af_gb_get_null_terminated(&data2, &size2);

  if (new_str != NULL && new_str2 != NULL) {
    apr_pool_initialize();
    apr_pool_t *v = NULL;
    apr_pool_create(&v, NULL);

    apr_bucket_alloc_t *bucket = apr_bucket_alloc_create(v);
    apr_bucket_brigade *brigade = apr_brigade_create(v, bucket);
    apr_brigade_write(brigade, NULL, NULL, new_str, strlen(new_str));

    apreq_parser_t parser;
    parser.content_type = new_str2;
    parser.temp_dir = "/tmp/";
    parser.brigade_limit = 10;
    parser.pool = v;
    parser.ctx = NULL;
    parser.bucket_alloc = bucket;

    parser.hook = apreq_hook_make(parser.pool, hookfunc, NULL, parser.ctx);

    apr_table_t *table = apr_table_make(parser.pool, 10);
    if (af_get_short(&data2, &size2) % 2 == 0) {
      apreq_parse_multipart(&parser, table, brigade);
    } else {
      apreq_parse_urlencoded(&parser, table, brigade);
    }

    apr_pool_terminate();
  }
  af_gb_cleanup();
  return 0;
}

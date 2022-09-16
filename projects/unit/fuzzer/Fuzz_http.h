/* Copyright 2022 Google LLC
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
#include <nxt_main.h>
#include "nxt_tests.h"

nxt_int_t nxt_http_parse_fuzz(nxt_thread_t *thr, nxt_str_t *request, nxt_lvlhsh_t *hash);

nxt_int_t
nxt_http_test_header_return(void *ctx, nxt_http_field_t *field, uintptr_t data)
{
  return data;
}

nxt_http_field_proc_t  nxt_http_test_bench_fields[] = {
    { nxt_string("Host"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("User-Agent"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Accept"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Accept-Encoding"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Accept-Language"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Connection"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Content-Length"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Content-Range"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Content-Type"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Cookie"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Range"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("If-Range"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Transfer-Encoding"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Expect"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Via"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("If-Modified-Since"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("If-Unmodified-Since"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("If-Match"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("If-None-Match"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Referer"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Date"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Upgrade"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Authorization"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Keep-Alive"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("X-Forwarded-For"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("X-Forwarded-Host"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("X-Forwarded-Proto"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("X-Http-Method-Override"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("X-Real-IP"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("X-Request-ID"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("TE"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Pragma"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Cache-Control"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Origin"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Upgrade-Insecure-Requests"),
      &nxt_http_test_header_return, NXT_OK },
};

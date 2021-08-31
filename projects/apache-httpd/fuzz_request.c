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
#include "http_core.h"

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

static const char *http_scheme2(const request_rec *r) {
  /*
   * The http module shouldn't return anything other than
   * "http" (the default) or "https".
   */
  if (r->server->server_scheme &&
      (strcmp(r->server->server_scheme, "https") == 0))
    return "https";

  return "http";
}

extern request_rec *ap_create_request(conn_rec *conn);
extern int read_request_line(request_rec *r, apr_bucket_brigade *bb);

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  apr_pool_create(&apr_hook_global_pool, NULL);
  ap_open_stderr_log(apr_hook_global_pool);
  ap_hook_http_scheme(http_scheme2, NULL, NULL, APR_HOOK_REALLY_LAST);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  af_gb_init();

  const uint8_t *data2 = data;
  size_t size2 = size;

  /* get random data for the fuzzer */
  char *new_str = af_gb_get_null_terminated(&data2, &size2);
  char *new_str2 = af_gb_get_null_terminated(&data2, &size2);
  char *new_str3 = af_gb_get_null_terminated(&data2, &size2);
  char *new_str4 = af_gb_get_null_terminated(&data2, &size2);
  char *new_str5 = af_gb_get_null_terminated(&data2, &size2);
  if (new_str != NULL && 
      new_str2 != NULL && 
      new_str3 != NULL &&
      new_str4 != NULL && 
      new_str5 != NULL) {

    /* this is the main fuzzing logic */

    apr_pool_initialize();
    apr_pool_t *v = NULL;
    apr_pool_create(&v, NULL);

    conn_rec conn;
    conn.pool = v;
    server_rec base_server;
    conn.base_server = &base_server;
    conn.bucket_alloc = apr_bucket_alloc_create(conn.pool);
    ap_method_registry_init(conn.pool);

    //server_rec server;

    /* Simulate ap_read_request */
    request_rec *r = NULL;
    r = ap_create_request(&conn);

    /* create a logs array for the request */
    struct ap_logconf logs = {};
    char *log_levels = calloc(1000, 1);
    memset(log_levels, 0, 1000);
    logs.module_levels = log_levels;
    r->log = &logs;
    if (r != NULL) {
      apr_bucket_brigade *tmp_bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
      conn.keepalive = AP_CONN_UNKNOWN;

      ap_run_pre_read_request(r, conn);

      core_server_config conf_mod;
      conf_mod.http_conformance   = (char)af_get_short(&data2, &size2);
      conf_mod.http09_enable      = (char)af_get_short(&data2, &size2);
      conf_mod.http_methods       = (char)af_get_short(&data2, &size2);
      void **module_config_arr = malloc(1000);
      module_config_arr[0] = &conf_mod;

      r->server->module_config = module_config_arr;
      ap_set_core_module_config(r->server->module_config, &conf_mod);

      /* randomise content of request */
      r->unparsed_uri           = new_str;
      r->uri                    = new_str2;
      r->server->server_scheme  = new_str3;
      r->method                 = new_str4;
      r->the_request            = new_str5;

      /* main target */
      ap_parse_request_line(r);

      free(module_config_arr);
    }
    free(log_levels);
    apr_pool_terminate();
  }

  af_gb_cleanup();
  return 0;
}

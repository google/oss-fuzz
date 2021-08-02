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

  // Targets that do not require a pool
  ap_cstr_casecmp(new_str, new_str);
  ap_getparents(new_str);
  ap_unescape_url(new_str);
  ap_unescape_urlencoded(new_str);
  ap_strcmp_match(new_str, "AAAAAABDKJSAD");

  // Pool initialisation
  if (apr_pool_initialize() == APR_SUCCESS) {
    apr_pool_t *pool = NULL;
    apr_pool_create(&pool, NULL);

    // Targets that require a pool
    ap_field_noparam(pool, new_str);

    ap_escape_shell_cmd(pool, new_str);
    ap_os_escape_path(pool, new_str, 0);
    ap_escape_html2(pool, new_str, 0);
    ap_escape_logitem(pool, new_str);

    // This line causes some issues if something bad is allocated
    ap_escape_quotes(pool, new_str);

    if (size > 2) {
      ap_cstr_casecmpn(new_str, new_str + 2, size - 2);
    }

    char *d = malloc(size * 2);
    ap_escape_errorlog_item(d, new_str, size * 2);
    free(d);

    // base64
    char *decoded = NULL;
    decoded = ap_pbase64decode(pool, new_str);
    ap_pbase64encode(pool, new_str);

    char *tmp_s = new_str;
    ap_getword_conf2(pool, &tmp_s);

    // str functions
    ap_strcasecmp_match(tmp_s, "asdfkj");
    ap_strcasestr(tmp_s, "AAAAAAAAAAAAAA");
    ap_strcasestr(tmp_s, "AasdfasbA");
    ap_strcasestr(tmp_s, "1341234");
    ap_strcasestr("AAAAAAAAAAAAAA", tmp_s);
    ap_strcasestr("AasdfasbA", tmp_s);
    ap_strcasestr("1341234", tmp_s);

    // List functions
    tmp_s = new_str;
    ap_get_list_item(pool, &tmp_s);
    tmp_s = new_str;
    ap_find_list_item(pool, &tmp_s, "kjahsdfkj");
    ap_find_token(pool, tmp_s, "klsjdfk");
    ap_find_last_token(pool, tmp_s, "sdadf");
    ap_is_chunked(pool, tmp_s);

    apr_array_header_t *offers = NULL;
    ap_parse_token_list_strict(pool, new_str, &offers, 0);

    char *tmp_null = NULL;
    ap_pstr2_alnum(pool, new_str, &tmp_null);

    // Word functions
    tmp_s = new_str;
    ap_getword(pool, &tmp_s, 0);

    tmp_s = new_str;
    ap_getword_white_nc(pool, &tmp_s);

    tmp_s = new_str;
    ap_get_token(pool, &tmp_s, 1);

    tmp_s = new_str;
    ap_escape_urlencoded(pool, tmp_s);

    apr_interval_time_t timeout;
    ap_timeout_parameter_parse(new_str, &timeout, "ms");

    tmp_s = new_str;
    ap_content_type_tolower(tmp_s);

    // Cleanup
    apr_pool_terminate();
  }
  free(new_str);
  return 0;
}

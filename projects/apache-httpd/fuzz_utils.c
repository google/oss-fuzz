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
#include "apr_portable.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_thread_proc.h"
#include "apr_signal.h"
#include "apr_thread_mutex.h"
#include "apr_proc_mutex.h"
#include "apr_poll.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_file_io.h"
#include "apr_fnmatch.h"

#include "apr_want.h"
#include "apr_poll.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "ap_listen.h"
#include "ap_regex.h"
#include "ap_expr.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *new_str = (char *)malloc(size+1);
    if (new_str == NULL){
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
    apr_pool_initialize();
    apr_pool_t *v = NULL;
    apr_pool_create(&v, NULL);

    // Targets that require a pool
    ap_field_noparam(v, new_str);

    ap_escape_shell_cmd(v, new_str);
    ap_os_escape_path(v, new_str, 0);
    ap_escape_html2(v, new_str, 0);
    ap_escape_logitem(v, new_str);
    ap_escape_quotes(v, new_str);

    if (size > 2) {
      ap_cstr_casecmpn(new_str, new_str+2, size-2);
    }

    char *d = malloc(size*2);
    ap_escape_errorlog_item(d, new_str, size*2);
    free(d);

    char *decoded = NULL;
    decoded = ap_pbase64decode(v, new_str);

    // Cleanup
    apr_pool_terminate();
    free(new_str);
    return 0;
}

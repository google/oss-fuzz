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

#include <string.h>
#include <unistd.h>

#include "ada_fuzz_header.h"


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Initialize fuzzing garbage collector. We use this to easily
  // get data types seeded with random input from the fuzzer.
  af_gb_init();

  const uint8_t *data2 = data;
  size_t size2 = size;

  char *new_str = af_gb_get_null_terminated(&data2, &size2);
  char *new_dst = af_gb_get_null_terminated(&data2, &size2);
  if (new_str != NULL && new_dst != NULL) {
    size_t new_str_len = strlen(new_str);

    // Targets that do not require a pool

    ap_cstr_casecmp(new_str, new_dst);
    if (new_str_len > 2) {
      ap_cstr_casecmpn(new_str, new_str + 2, new_str_len - 2);
    }
    ap_strcmp_match(new_str, new_dst);
    ap_strcasecmp_match(new_str, new_dst);
    ap_strcasestr(new_str, new_dst);

    apr_interval_time_t timeout;
    ap_timeout_parameter_parse(new_str, &timeout, "ms");

    new_dst = af_gb_get_null_terminated(&data2, &size2);
    if (new_dst != NULL) {
      ap_getparents(new_dst);
    }

    new_dst = af_gb_get_null_terminated(&data2, &size2);
    if (new_dst != NULL) {
      ap_no2slash(new_dst);
    }

    new_dst = af_gb_get_null_terminated(&data2, &size2);
    if (new_dst != NULL) {
      ap_unescape_url(new_dst);
    }

    new_dst = af_gb_get_null_terminated(&data2, &size2);
    if (new_dst != NULL) {
      ap_unescape_urlencoded(new_dst);
    }

    new_dst = af_gb_get_null_terminated(&data2, &size2);
    if (new_dst != NULL) {
      ap_content_type_tolower(new_dst);
    }

    new_dst = malloc(new_str_len*3+1); // big enough for worst-case URL-escaped (%nn)
    ap_escape_path_segment_buffer(new_dst, new_str);
    free(new_dst);

    new_dst = malloc(new_str_len*4+1); // big enough for worst-case log-escaped (\xnn)
    ap_escape_errorlog_item(new_dst, new_str, new_str_len*4+1);
    free(new_dst);

    // Pool initialisation
    if (apr_pool_initialize() == APR_SUCCESS) {
      apr_pool_t *pool = NULL;
      apr_pool_create(&pool, NULL);

      // Targets that require a pool

      new_dst = af_gb_get_null_terminated(&data2, &size2);
      if (new_dst != NULL) {
        ap_make_dirstr_parent(pool, new_dst);
      }

      ap_field_noparam(pool, new_str);

      ap_escape_shell_cmd(pool, new_str);
      ap_os_escape_path(pool, new_str, 0);
      ap_escape_html2(pool, new_str, 0);
      ap_escape_logitem(pool, new_str);

      // This line causes some issues if something bad is allocated
      ap_escape_quotes(pool, new_str);

      // base64
      ap_pbase64decode(pool, new_str);
      ap_pbase64encode(pool, new_str);
      new_dst = af_gb_get_null_terminated(&data2, &size2);
      if (new_dst != NULL) {
        char *d;
        apr_size_t dlen;
        ap_pbase64decode_strict(pool, new_dst, &d, &dlen);
      }

      // List functions
      const char *tmp_s = new_str;
      ap_get_list_item(pool, &tmp_s);
      ap_find_list_item(pool, new_str, "kjahsdfkj");
      ap_find_token(pool, new_str, "klsjdfk");
      ap_find_last_token(pool, new_str, "sdadf");
      apr_array_header_t *offers = NULL;
      ap_parse_token_list_strict(pool, new_str, &offers, 0);

      tmp_s = new_str;
      ap_get_token(pool, &tmp_s, 1);

      tmp_s = NULL;
      ap_pstr2_alnum(pool, new_str, &tmp_s);

      ap_is_chunked(pool, new_str);

      // Word functions
      tmp_s = new_str;
      ap_getword(pool, &tmp_s, 0);
      tmp_s = new_str;
      ap_getword_conf2(pool, &tmp_s);
      new_dst = af_gb_get_null_terminated(&data2, &size2);
      if (new_dst != NULL) {
        char *d = new_dst;
        ap_getword_white_nc(pool, &d);
      }

      ap_escape_urlencoded(pool, new_str);


			char filename[256];
			sprintf(filename, "/tmp/libfuzzer.%d", getpid());
			FILE *fp = fopen(filename, "wb");
			fwrite(data, size, 1, fp);
			fclose(fp);

			// Fuzzer logic here
			ap_configfile_t *cfg;
			ap_pcfg_openfile(&cfg, pool, filename);
      char tmp_line[100];
      if ((af_get_short(&data2, &size2) % 2) == 0) {
        ap_cfg_getline(tmp_line, 100, cfg);
      }
      else {
        cfg->getstr = NULL;
        ap_cfg_getline(tmp_line, 100, cfg);
      }
			// Fuzzer logic end

			unlink(filename);

      // Cleanup
      apr_pool_terminate();
    }
  }

  // Cleanup all of the memory allocated by the fuzz headers.
  af_gb_cleanup();
  return 0;
}

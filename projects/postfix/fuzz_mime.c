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

#include <sys_defs.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

#include <mymalloc.h>
#include <msg.h>
#include <vstring.h>

#include <rec_type.h>
#include <is_header.h>
#include <header_opts.h>
#include <mail_params.h>
#include <header_token.h>
#include <lex_822.h>
#include <mime_state.h>

#include <stdlib.h>
#include <stdint.h>
#include <stringops.h>
#include <vstream.h>
#include <msg_vstream.h>
#include <rec_streamlf.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

// Define empty callback functions
static void head_out(void *context, int class, const HEADER_OPTS *unused_info,
                     VSTRING *buf, off_t offset) {}
static void head_end(void *context) {}
static void body_end(void *context) {}
static void err_print(void *unused_context, int err_flag, const char *text,
                      ssize_t len) {}
static void body_out(void *context, int rec_type, const char *buf, ssize_t len,
                     off_t offset) {}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *new_str = (char *)malloc(size + 1);
  if (new_str == NULL) {
    return 0;
  }
  memcpy(new_str, data, size);
  new_str[size] = '\0';

#define MIME_OPTIONS                                                           \
  (MIME_OPT_REPORT_8BIT_IN_7BIT_BODY | MIME_OPT_REPORT_8BIT_IN_HEADER |        \
   MIME_OPT_REPORT_ENCODING_DOMAIN | MIME_OPT_REPORT_TRUNC_HEADER |            \
   MIME_OPT_REPORT_NESTING | MIME_OPT_DOWNGRADE)

  int rec_type = REC_TYPE_NORM;
  int err;

  // Simple single call of mime_state_update for now.
  MIME_STATE *state;
  msg_vstream_init("fuzz_mime", VSTREAM_OUT);
  state = mime_state_alloc(MIME_OPTIONS, head_out, head_end, body_out, body_end,
                           err_print, (void *)VSTREAM_OUT);
  mime_state_update(state, rec_type, new_str, size);
  mime_state_free(state);

  free(new_str);
  return 0;
}

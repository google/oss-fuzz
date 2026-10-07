/*
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *nstr = (char *)malloc(size + 1);
  if (nstr == NULL) {
    return 0;
  }
  memcpy(nstr, data, size);
  nstr[size] = '\0';

  guchar *tmp = NULL;
  gsize retlen;

  if (size % 2 == 0 && strlen(nstr) > 0) {
    tmp = purple_base16_decode(nstr, &retlen);
    if (tmp != NULL) {
      g_free(tmp);
    }
  }

  tmp = NULL;
  tmp = purple_quotedp_decode(nstr, &retlen);
  if (tmp != NULL) {
    g_free(tmp);
  }

  char *tmp2 = NULL;
  tmp2 = purple_mime_decode_field(nstr);
  if (tmp2 != NULL) {
    free(tmp2);
  }

  purple_str_to_time(nstr, TRUE, NULL, NULL, NULL);

  gchar *xhtml = NULL;
  gchar *plaintext = NULL;
  purple_markup_html_to_xhtml(nstr, &xhtml, &plaintext);

  if (xhtml != NULL) {
    g_free(xhtml);
  }

  if (plaintext != NULL) {
    g_free(plaintext);
  }

  char *tmp3 = purple_markup_strip_html(nstr);
  if (tmp3 != NULL) {
    free(tmp3);
  }

  purple_markup_is_rtl(nstr);

  free(nstr);
  return 0;
}

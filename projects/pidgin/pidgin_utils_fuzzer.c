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

  /*
    guchar *
    purple_quotedp_decode(const char *str, gsize *ret_len)
  */
  tmp = NULL;
  tmp = purple_quotedp_decode(nstr, &retlen);
  if (tmp != NULL) {
    g_free(tmp);
  }

  free(nstr);
  return 0;
}


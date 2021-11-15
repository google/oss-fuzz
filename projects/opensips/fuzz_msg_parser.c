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
#include "../parser/sdp/sdp.h"

#include "../cachedb/test/test_cachedb.h"
#include "../lib/test/test_csv.h"
#include "../mem/test/test_malloc.h"
#include "../str.h"

#include "../context.h"
#include "../dprint.h"
#include "../globals.h"
#include "../lib/list.h"
#include "../sr_module.h"
#include "../sr_module_deps.h"

int LLVMFuzzerTestOneInput(const char *data, size_t size) {
  ensure_global_context();
  struct sip_uri u;

  if (size <= 1) {
    return 0;
  }

  struct sip_msg orig_inv = {};
  orig_inv.buf = (char *)data;
  orig_inv.len = size;

  parse_msg(orig_inv.buf, orig_inv.len, &orig_inv);
  free_sip_msg(&orig_inv);
  return 0;
}

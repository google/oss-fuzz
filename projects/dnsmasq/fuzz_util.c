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

#include "fuzz_header.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // init fuzz garbage collector
  gb_init();

  int succ = init_daemon(&data, &size);
  if (succ == 0) {
    char *t1 = gb_get_len_null_terminated(&data, &size, MAXDNAME);
    char *t2 = gb_get_len_null_terminated(&data, &size, MAXDNAME);
    if (t1 != NULL && t2 != NULL) {

      // Util logic
      hostname_isequal(t1, t2);

      legal_hostname(t1);
      char *tmp = canonicalise(t2, NULL);
      if (tmp != NULL) {
        free(tmp);
      }

      char *tmp_out = (char *)malloc(30);
      int mac_type;
      parse_hex(t1, (unsigned char *)tmp_out, 30, NULL, NULL);
      parse_hex(t1, (unsigned char *)tmp_out, 30, NULL, &mac_type);
      free(tmp_out);

      wildcard_match(t1, t2);
      if (strlen(t1) < strlen(t2)) {
        wildcard_matchn(t1, t2, strlen(t1));
      } else {
        wildcard_matchn(t1, t2, strlen(t2));
      }
      hostname_issubdomain(t1, t2);

      union all_addr addr1;
      memset(&addr1, 0, sizeof(union all_addr));
      is_name_synthetic(0, t1, &addr1);

      if (size > sizeof(struct dns_header)) {
        hash_questions(data, size, t2);

        rrfilter(data, size, 0);
      }
    }

    fuzz_blockdata_cleanup();
  }

  // cleanup
  gb_cleanup();

  return 0;
}

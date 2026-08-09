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
#include <config.h>

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

#include "bluetooth.h"
#include "sdp.h"
#include "sdp_lib.h"
#include "sdp-xml.h"

void empty_func(void *d, const char *s) {
  return;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  sdp_record_t *rec;
  rec = sdp_xml_parse_record(data, size);
  if (rec != NULL) {
    convert_sdp_record_to_xml(rec, 0, empty_func);
    sdp_record_free(rec);
  }

  return 0;
}

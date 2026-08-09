/*
# Copyright 2023 Google LLC
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

/*
  Usage:
    python infra/helper.py build_image libical
    python infra/helper.py build_fuzzers --sanitizer undefined|address|memory libical
    python infra/helper.py run_fuzzer libical libical_extended_fuzzer
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *ical_string1 = (char*)malloc(size + 1);
    memcpy(ical_string1, data, size);
    ical_string1[size] = '\0';

    icalcomponent *ical1 = icalcomponent_new_from_string(ical_string1);
    if (ical1 != NULL) {
        icalcomponent_normalize(ical1);
    }
    icalcomponent_free(ical1);
    free(ical_string1);

    return 0;
}

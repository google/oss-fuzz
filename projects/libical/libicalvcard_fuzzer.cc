/*
# Copyright 2026 Google LLC
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
    python infra/helper.py run_fuzzer libical libicalvcard_fuzzer
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libical/ical.h>
#include <libical/vcard.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *vcard_string = (char*)malloc(size + 1);
    memcpy(vcard_string, data, size);
    vcard_string[size] = '\0';

    vcardcomponent *card = vcardparser_parse_string(vcard_string);
    vcardcomponent_free(card);

    free(vcard_string);

    return 0;
}

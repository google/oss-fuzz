// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

/*
 * OSS-Fuzz harness for ldns DNS RR text parser.
 * Exercises ldns_rr_new_frm_str() — the text-format resource record parser.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ldns/ldns.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;

    /* Null-terminate for string parsing */
    char *str = malloc(size + 1);
    if (!str)
        return 0;
    memcpy(str, data, size);
    str[size] = '\0';

    ldns_rr *rr = NULL;
    ldns_rdf *origin = NULL;
    ldns_rdf *prev = NULL;
    uint32_t default_ttl = 3600;

    ldns_status status = ldns_rr_new_frm_str(&rr, str, default_ttl, origin, &prev);
    if (status == LDNS_STATUS_OK && rr != NULL) {
        ldns_rr_free(rr);
    }
    if (prev != NULL) {
        ldns_rdf_free(prev);
    }

    free(str);
    return 0;
}

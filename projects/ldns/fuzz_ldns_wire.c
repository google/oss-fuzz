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
 * OSS-Fuzz harness for ldns DNS wire format parser.
 * Exercises ldns_wire2pkt() — the primary entry point for parsing
 * raw DNS message bytes received from the network.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ldns/ldns.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ldns_pkt *pkt = NULL;
    ldns_status status;

    if (size == 0)
        return 0;

    /* Parse raw DNS wire message */
    status = ldns_wire2pkt(&pkt, data, size);
    if (status == LDNS_STATUS_OK && pkt != NULL) {
        /* Exercise the printing path to cover more code */
        ldns_buffer *buf = ldns_buffer_new(4096);
        if (buf) {
            ldns_pkt2buffer_str(buf, pkt);
            ldns_buffer_free(buf);
        }
        ldns_pkt_free(pkt);
    }

    return 0;
}

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
 * OSS-Fuzz harness for NSD DNS packet query section parser.
 * Exercises packet_read_query_section() and answer_query() through
 * the buffer abstraction used when processing incoming DNS queries.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "packet.h"
#include "region-allocator.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 12)  /* DNS header is 12 bytes */
        return 0;

    region_type *region = region_create(xalloc, free);
    if (!region)
        return 0;

    /* Wrap fuzz input in an NSD buffer */
    buffer_type *packet = buffer_create_from(region, (void *)data, size);

    /* Attempt to parse the query section after skipping the 12-byte header */
    buffer_set_position(packet, 12);

    uint8_t qnamebuf[MAXDOMAINLEN + 1];
    uint16_t qtype = 0, qclass = 0;

    packet_read_query_section(packet, qnamebuf, &qtype, &qclass);

    region_destroy(region);
    return 0;
}

// Copyright 2025 Google LLC.
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

/*
 * Fuzz the hiredis RESP protocol reader (redisReader) covering:
 *  - Simple strings (+OK\r\n)
 *  - Errors (-ERR ...\r\n)
 *  - Integers (:1234\r\n)
 *  - Bulk strings ($5\r\nhello\r\n)
 *  - Arrays (*3\r\n...
 *  - Inline commands
 *  - RESP3 aggregate types (%, ~, |, >, =)
 *  - Partial / fragmented feeds
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hiredis.h"
#include "read.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0)
        return 0;

    /* Use first byte as mode selector */
    uint8_t mode = data[0] & 0x03;
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    redisReader *reader = redisReaderCreate();
    if (!reader)
        return 0;

    if (mode == 0) {
        /* Feed all at once */
        redisReaderFeed(reader, (const char *)payload, payload_len);
    } else if (mode == 1) {
        /* Feed byte by byte to exercise partial-input paths */
        for (size_t i = 0; i < payload_len; i++) {
            if (redisReaderFeed(reader, (const char *)(payload + i), 1) != REDIS_OK)
                break;
        }
    } else if (mode == 2 && payload_len >= 2) {
        /* Feed in two chunks at a random split point */
        size_t split = payload[0] % (payload_len - 1) + 1;
        redisReaderFeed(reader, (const char *)payload, split);
        redisReaderFeed(reader, (const char *)(payload + split), payload_len - split);
    } else {
        /* Feed in 4-byte chunks */
        for (size_t i = 0; i < payload_len; i += 4) {
            size_t chunk = payload_len - i < 4 ? payload_len - i : 4;
            if (redisReaderFeed(reader, (const char *)(payload + i), chunk) != REDIS_OK)
                break;
        }
    }

    /* Drain all available replies */
    void *reply = NULL;
    int max_replies = 64;
    while (max_replies-- > 0) {
        int ret = redisReaderGetReply(reader, &reply);
        if (ret != REDIS_OK || reply == NULL)
            break;
        freeReplyObject(reply);
        reply = NULL;
    }

    redisReaderFree(reader);
    return 0;
}

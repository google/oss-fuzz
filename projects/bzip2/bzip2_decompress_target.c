/*
# Copyright 2018 Google Inc.
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
###############################################################################
*/

#include "bzlib.h"
#include <limits.h>
#include <stdint.h>
#include <string.h>

#define OUTPUT_BUFFER_SIZE 4096
/* Bound work on valid decompression bombs without limiting the input ratio. */
#define MAX_OUTPUT_SIZE (16 * 1024 * 1024)

static void
decompress(const uint8_t *data, size_t size, int small)
{
    bz_stream stream;
    char outbuf[OUTPUT_BUFFER_SIZE];
    size_t total_out = 0;
    int r;

    memset(&stream, 0, sizeof(stream));
    r = BZ2_bzDecompressInit(&stream, /*verbosity=*/0, small);
    if (r != BZ_OK) {
        return;
    }

    stream.next_in = (char *)data;
    stream.avail_in = (unsigned int)size;
    do {
        unsigned int before_in = stream.avail_in;

        stream.next_out = outbuf;
        stream.avail_out = sizeof(outbuf);
        r = BZ2_bzDecompress(&stream);
        total_out += sizeof(outbuf) - stream.avail_out;

        /* BZ_OK without consuming input or producing output needs more data. */
        if (r == BZ_OK && before_in == stream.avail_in &&
                stream.avail_out == sizeof(outbuf)) {
            break;
        }
    } while (r == BZ_OK && total_out < MAX_OUTPUT_SIZE &&
            (stream.avail_in != 0 || stream.avail_out == 0));

    BZ2_bzDecompressEnd(&stream);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > UINT_MAX) {
        return 0;
    }

    decompress(data, size, /*small=*/size % 2);
    return 0;
}

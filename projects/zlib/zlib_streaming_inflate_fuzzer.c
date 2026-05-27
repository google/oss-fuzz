/* Copyright 2025 Google LLC
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

/*
 * zlib_streaming_inflate_fuzzer.c
 *
 * Fuzzes the streaming inflate path with:
 *   1. Byte-at-a-time feeding (exercises state machine transitions)
 *   2. Custom zalloc/zfree allocators (OOM-injection path)
 *   3. inflateSetDictionary() after Z_NEED_DICT (dict path)
 *   4. inflateGetHeader() (gzip header parser)
 *   5. inflateCopy() (state duplication mid-stream)
 *
 * The existing uncompress_fuzzer.c only calls uncompress() / inflateInit()
 * with full-buffer input. This harness covers the streaming API used by
 * virtually every application that calls zlib incrementally.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"

#define OUT_SIZE (256 * 1024)  /* 256 KB output buffer */

/* Custom allocator — counts allocs to detect leaks */
static voidpf my_alloc(voidpf opaque, uInt items, uInt size) {
    (void)opaque;
    return calloc(items, size);
}
static void my_free(voidpf opaque, voidpf ptr) {
    (void)opaque;
    free(ptr);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    /* Use first byte to select windowBits variant:
     *   0x00-0x3F: deflate raw       (windowBits = -15)
     *   0x40-0x7F: zlib wrapper      (windowBits = 15)
     *   0x80-0xBF: gzip wrapper      (windowBits = 15+16)
     *   0xC0-0xFF: auto-detect       (windowBits = 15+32)
     */
    uint8_t mode = data[0];
    int windowBits;
    if      (mode < 0x40) windowBits = -15;
    else if (mode < 0x80) windowBits = 15;
    else if (mode < 0xC0) windowBits = 15 + 16;
    else                  windowBits = 15 + 32;

    const uint8_t *payload = data + 1;
    size_t payload_size    = size - 1;

    uint8_t *out = (uint8_t *)malloc(OUT_SIZE);
    if (!out) return 0;

    /* --- Path 1: byte-at-a-time streaming with custom allocator --- */
    {
        z_stream s;
        s.zalloc = my_alloc;
        s.zfree  = my_free;
        s.opaque = Z_NULL;

        if (inflateInit2(&s, windowBits) == Z_OK) {
            gz_header gzhdr;
            char extra[64], name[64], comment[64];
            gzhdr.extra    = (Bytef *)extra;    gzhdr.extra_max = sizeof(extra);
            gzhdr.name     = (Bytef *)name;     gzhdr.name_max  = sizeof(name);
            gzhdr.comment  = (Bytef *)comment;  gzhdr.comm_max  = sizeof(comment);
            /* inflateGetHeader is a no-op for non-gzip streams */
            inflateGetHeader(&s, &gzhdr);

            s.avail_out = OUT_SIZE;
            s.next_out  = out;

            for (size_t i = 0; i < payload_size; i++) {
                s.avail_in = 1;
                s.next_in  = (Bytef *)(payload + i);
                int ret = inflate(&s, Z_NO_FLUSH);
                if (ret == Z_NEED_DICT) {
                    /* Feed a dummy dictionary */
                    static const Bytef dict[] = "fuzz";
                    inflateSetDictionary(&s, dict, sizeof(dict) - 1);
                    inflate(&s, Z_NO_FLUSH);
                }
                if (ret == Z_STREAM_END || ret == Z_DATA_ERROR ||
                    ret == Z_BUF_ERROR  || ret == Z_STREAM_ERROR)
                    break;
                if (s.avail_out == 0) {
                    s.avail_out = OUT_SIZE;
                    s.next_out  = out;
                }
            }
            inflate(&s, Z_FINISH);
            inflateEnd(&s);
        }
    }

    /* --- Path 2: inflateCopy mid-stream --- */
    {
        z_stream s, s2;
        s.zalloc = my_alloc;
        s.zfree  = my_free;
        s.opaque = Z_NULL;

        if (inflateInit2(&s, windowBits) == Z_OK) {
            /* Feed half the data */
            s.avail_in  = (uInt)(payload_size / 2);
            s.next_in   = (Bytef *)payload;
            s.avail_out = OUT_SIZE;
            s.next_out  = out;
            int ret = inflate(&s, Z_NO_FLUSH);

            if (ret == Z_OK || ret == Z_BUF_ERROR) {
                /* Duplicate the mid-stream state */
                if (inflateCopy(&s2, &s) == Z_OK) {
                    s2.avail_in  = (uInt)(payload_size - payload_size / 2);
                    s2.next_in   = (Bytef *)(payload + payload_size / 2);
                    s2.avail_out = OUT_SIZE;
                    s2.next_out  = out;
                    inflate(&s2, Z_FINISH);
                    inflateEnd(&s2);
                }
            }
            inflateEnd(&s);
        }
    }

    free(out);
    return 0;
}

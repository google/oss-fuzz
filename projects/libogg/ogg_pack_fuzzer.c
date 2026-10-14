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
 * ogg_pack_fuzzer.c
 *
 * Fuzzing harness for the libogg bit-packing layer (oggpack_buffer).
 *
 * The oggpack API is used by higher-level Ogg codecs (Vorbis, Opus, Theora)
 * to read/write variable-width integers from bitstreams. Integer overflows
 * and OOB reads in this layer affect ALL Ogg-based codecs.
 *
 * This harness exercises:
 *   oggpack_readinit()  / oggpack_read()  / oggpack_look()  / oggpack_adv()
 *   oggpackB_readinit() / oggpackB_read() / oggpackB_look() / oggpackB_adv()
 *   (both LSB-first and MSB-first variants)
 *   oggpack_writeinit() / oggpack_write() / oggpack_writeclear()
 *   (write path to catch buffer-management overflows)
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ogg/ogg.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    /* --- Read path (LSB-first) --- */
    {
        oggpack_buffer rb;
        oggpack_readinit(&rb, (unsigned char *)data, (int)size);

        /* Read bits in varying widths: 1, 4, 7, 8, 13, 17, 24, 32 */
        static const int widths[] = {1, 4, 7, 8, 13, 17, 24, 32};
        for (size_t i = 0; i < sizeof(widths)/sizeof(widths[0]); i++) {
            int w = widths[i];
            oggpack_look(&rb, w);
            oggpack_read(&rb, w);
        }
        /* Advance to end */
        while (oggpack_bits(&rb) < (long)size * 8 - 32) {
            oggpack_adv(&rb, 8);
            if (oggpack_read(&rb, 1) < 0) break;
        }
    }

    /* --- Read path (MSB-first) --- */
    {
        oggpack_buffer rb;
        oggpackB_readinit(&rb, (unsigned char *)data, (int)size);
        static const int widths[] = {1, 4, 7, 8, 13, 17, 24, 32};
        for (size_t i = 0; i < sizeof(widths)/sizeof(widths[0]); i++) {
            int w = widths[i];
            oggpackB_look(&rb, w);
            oggpackB_read(&rb, w);
        }
    }

    /* --- Write path: replay fuzz bytes as bit widths/values --- */
    {
        oggpack_buffer wb;
        oggpack_writeinit(&wb);

        for (size_t i = 0; i + 1 < size; i += 2) {
            int bits  = (data[i] & 0x1F) + 1;   /* 1-32 bits */
            unsigned long val = data[i+1];
            oggpack_write(&wb, val, bits);
        }

        /* Read back what we wrote */
        long written_bytes = oggpack_bytes(&wb);
        unsigned char *buf = oggpack_get_buffer(&wb);
        if (buf && written_bytes > 0) {
            oggpack_buffer rb2;
            oggpack_readinit(&rb2, buf, (int)written_bytes);
            for (size_t i = 0; i + 1 < size; i += 2) {
                int bits = (data[i] & 0x1F) + 1;
                if (oggpack_read(&rb2, bits) < 0) break;
            }
        }

        oggpack_writeclear(&wb);
    }

    return 0;
}

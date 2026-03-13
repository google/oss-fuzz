// Copyright 2025 Google LLC
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

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define MINIMP3_IMPLEMENTATION
#define MINIMP3_ALLOW_MONO_STEREO_TRANSITION
#include "minimp3_ex.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8)
        return 0;
    if (size > 128 * 1024)
        size = 128 * 1024;

    /* Consume first 4 bytes for seek position and flags */
    uint32_t seek_pos = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                        ((uint32_t)data[2] << 8)  | (uint32_t)data[3];
    int flags = (data[4] & 0x01) ? MP3D_SEEK_TO_BYTE : MP3D_SEEK_TO_SAMPLE;
    flags |= MP3D_ALLOW_MONO_STEREO_TRANSITION;

    const uint8_t *buf = data + 5;
    size_t buf_size = size - 5;

    mp3dec_ex_t dec;
    if (mp3dec_ex_open_buf(&dec, buf, buf_size, flags) == 0) {
        /* Read some samples */
        mp3d_sample_t pcm[MINIMP3_MAX_SAMPLES_PER_FRAME];
        size_t read_total = 0;
        size_t readed;

        do {
            readed = mp3dec_ex_read(&dec, pcm, MINIMP3_MAX_SAMPLES_PER_FRAME);
            read_total += readed;
            /* Safety: limit total reads to prevent excessive runtime */
            if (read_total > 1024 * 1024)
                break;
        } while (readed > 0);

        /* Test seek */
        mp3dec_ex_seek(&dec, (uint64_t)seek_pos);

        /* Read after seek */
        readed = mp3dec_ex_read(&dec, pcm, MINIMP3_MAX_SAMPLES_PER_FRAME);
        (void)readed;

        mp3dec_ex_close(&dec);
    }

    return 0;
}

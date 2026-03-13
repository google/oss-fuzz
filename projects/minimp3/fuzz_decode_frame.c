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
#include <string.h>

#define MINIMP3_IMPLEMENTATION
#include "minimp3.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4)
        return 0;
    /* Cap input to avoid OOM on very large inputs */
    if (size > 128 * 1024)
        size = 128 * 1024;

    mp3dec_t dec;
    mp3dec_init(&dec);

    const uint8_t *buf = data;
    size_t remaining = size;

    /* Decode frames until the buffer is exhausted */
    while (remaining > 0) {
        mp3dec_frame_info_t info;
        mp3d_sample_t pcm[MINIMP3_MAX_SAMPLES_PER_FRAME];

        int samples = mp3dec_decode_frame(&dec, buf, (int)remaining, pcm, &info);

        if (info.frame_bytes > 0) {
            if ((size_t)info.frame_bytes > remaining)
                break;
            buf += info.frame_bytes;
            remaining -= info.frame_bytes;
        } else {
            /* No frame found, skip one byte */
            buf++;
            remaining--;
        }
    }

    return 0;
}

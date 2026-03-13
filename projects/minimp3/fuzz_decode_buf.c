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

static int iterate_cb(void *user_data, const uint8_t *frame, int frame_size,
                      int free_format_bytes, size_t buf_size, uint64_t offset,
                      mp3dec_frame_info_t *info) {
    (void)user_data;
    (void)frame;
    (void)frame_size;
    (void)free_format_bytes;
    (void)buf_size;
    (void)offset;
    (void)info;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4)
        return 0;
    if (size > 128 * 1024)
        size = 128 * 1024;

    /* Use first byte to select API path */
    uint8_t selector = data[0] & 0x01;
    const uint8_t *buf = data + 1;
    size_t buf_size = size - 1;

    if (selector == 0) {
        /* Test mp3dec_load_buf: full buffer decode */
        mp3dec_t dec;
        mp3dec_file_info_t info;
        memset(&info, 0, sizeof(info));

        mp3dec_load_buf(&dec, buf, buf_size, &info, NULL, NULL);

        if (info.buffer)
            free(info.buffer);
    } else {
        /* Test mp3dec_iterate_buf: frame iteration */
        mp3dec_iterate_buf(buf, buf_size, iterate_cb, NULL);
    }

    return 0;
}

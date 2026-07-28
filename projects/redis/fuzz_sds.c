/* Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "sds.h"

/* Fuzz the sdssplitargs() function which parses inline Redis commands
 * and configuration file arguments. This handles quoted strings,
 * hex escapes (\xNN), and various special characters. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 1024 * 64) return 0;

    /* sdssplitargs needs a null-terminated string */
    char *buf = malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    int argc = 0;
    sds *argv = sdssplitargs(buf, &argc);
    if (argv) {
        sdsfreesplitres(argv, argc);
    }

    /* Also test sdssplitlen with various separators */
    sds input = sdsnewlen(data, size);
    if (input) {
        int count;
        sds *parts = sdssplitlen(input, sdslen(input), "\r\n", 2, &count);
        if (parts) sdsfreesplitres(parts, count);
        sdsfree(input);
    }

    free(buf);
    return 0;
}

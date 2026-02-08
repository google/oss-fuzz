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
#include <string.h>
#include <stdlib.h>

/* Declarations from lib/wildmatch.h */
int wildmatch(const char *pattern, const char *text);
int iwildmatch(const char *pattern, const char *text);
int wildmatch_array(const char *pattern, const char *const *texts, int where);
int litmatch_array(const char *string, const char *const *texts, int where);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Need at least 2 bytes (1 for pattern, 1 for text separator) */
    if (size < 2 || size > 4096)
        return 0;

    /* Find a null byte to split input into pattern and text.
     * If no null found, split at the midpoint. */
    const uint8_t *sep = memchr(data, '\0', size);
    char *pattern, *text;

    if (sep && sep > data && (sep - data) < (ptrdiff_t)(size - 1)) {
        /* Use the null byte as separator */
        size_t pat_len = sep - data;
        size_t txt_len = size - pat_len - 1;

        pattern = (char *)malloc(pat_len + 1);
        text = (char *)malloc(txt_len + 1);
        if (!pattern || !text) {
            free(pattern);
            free(text);
            return 0;
        }

        memcpy(pattern, data, pat_len);
        pattern[pat_len] = '\0';
        memcpy(text, sep + 1, txt_len);
        text[txt_len] = '\0';
    } else {
        /* Split at midpoint */
        size_t mid = size / 2;
        pattern = (char *)malloc(mid + 1);
        text = (char *)malloc((size - mid) + 1);
        if (!pattern || !text) {
            free(pattern);
            free(text);
            return 0;
        }

        memcpy(pattern, data, mid);
        pattern[mid] = '\0';
        memcpy(text, data + mid, size - mid);
        text[size - mid] = '\0';
    }

    /* Exercise the wildmatch functions */
    wildmatch(pattern, text);
    iwildmatch(pattern, text);

    /* Also test the array-based matching */
    const char *texts[3];
    texts[0] = text;
    texts[1] = NULL;

    wildmatch_array(pattern, texts, 0);
    wildmatch_array(pattern, texts, 1);

    free(pattern);
    free(text);

    return 0;
}

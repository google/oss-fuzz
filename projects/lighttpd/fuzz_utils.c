/* Copyright 2026 Google LLC

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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "first.h"
#include "buffer.h"
#include "base64.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    uint8_t action = data[0];
    data++;
    size--;

    buffer *b = buffer_init();
    buffer_copy_string_len(b, (const char *)data, size);

    switch (action % 12) {
        case 0:
            buffer_urldecode_path(b);
            break;
        case 1:
            buffer_path_simplify(b);
            break;
        case 2:
            buffer_is_valid_UTF8(b);
            break;
        case 3:
            buffer_to_lower(b);
            break;
        case 4:
            buffer_to_upper(b);
            break;
        case 5:
            {
                buffer *dest = buffer_init();
                buffer_append_string_encoded(dest, b->ptr, buffer_clen(b), ENCODING_REL_URI);
                buffer_free(dest);
            }
            break;
        case 6:
            {
                buffer *dest = buffer_init();
                buffer_append_string_encoded(dest, b->ptr, buffer_clen(b), ENCODING_HTML);
                buffer_free(dest);
            }
            break;
        case 7:
            {
                buffer *dest = buffer_init();
                buffer_append_string_c_escaped(dest, b->ptr, buffer_clen(b));
                buffer_free(dest);
            }
            break;
        case 8:
            {
                buffer *dest = buffer_init();
                buffer_append_bs_escaped(dest, b->ptr, buffer_clen(b));
                buffer_free(dest);
            }
            break;
        case 9:
            {
                buffer *dest = buffer_init();
                buffer_append_bs_escaped_json(dest, b->ptr, buffer_clen(b));
                buffer_free(dest);
            }
            break;
        case 10:
            {
                buffer *dest = buffer_init();
                buffer_append_base64_enc(dest, (const unsigned char *)b->ptr, buffer_clen(b), BASE64_STANDARD, 1);
                buffer_free(dest);
            }
            break;
        case 11:
            {
                buffer *dest = buffer_init();
                buffer_append_base64_decode(dest, b->ptr, buffer_clen(b), BASE64_STANDARD);
                buffer_free(dest);
            }
            break;
    }

    buffer_free(b);

    return 0;
}

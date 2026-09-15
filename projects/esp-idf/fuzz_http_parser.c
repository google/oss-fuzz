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
#include <stdlib.h>
#include <string.h>

#include "http_parser.h"

static const http_parser_settings settings_null = {
    .on_message_begin    = 0,
    .on_url              = 0,
    .on_status           = 0,
    .on_header_field     = 0,
    .on_header_value     = 0,
    .on_headers_complete = 0,
    .on_body             = 0,
    .on_message_complete = 0,
    .on_chunk_header     = 0,
    .on_chunk_complete   = 0,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    /* Exercise all three parser modes against the same input. */
    enum http_parser_type modes[] = {HTTP_REQUEST, HTTP_RESPONSE, HTTP_BOTH};
    for (unsigned i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
        http_parser parser;
        http_parser_init(&parser, modes[i]);
        http_parser_execute(&parser, &settings_null,
                            (const char *)data, size);
    }

    return 0;
}

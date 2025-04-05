/*
# Copyright 2024 Google LLC
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
################################################################################
*/

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "api/yajl_parse.h"
#include "yajl_lex.h"
#include "yajl_parser.h"

// Minimal callbacks implementation
static int handle_null(void *ctx) { return 1; }
static int handle_boolean(void *ctx, int b) { return 1; }
static int handle_number(void *ctx, const char *n, unsigned int l) { return 1; }
static int handle_string(void *ctx, const unsigned char *s, unsigned int l) { return 1; }
static int handle_start_map(void *ctx) { return 1; }
static int handle_map_key(void *ctx, const unsigned char *k, unsigned int l) { return 1; }
static int handle_end_map(void *ctx) { return 1; }
static int handle_start_array(void *ctx) { return 1; }
static int handle_end_array(void *ctx) { return 1; }

static yajl_callbacks callbacks = {
    handle_null,
    handle_boolean,
    NULL, // integer callback
    NULL, // double callback
    handle_number,
    handle_string,
    handle_start_map,
    handle_map_key,
    handle_end_map,
    handle_start_array,
    handle_end_array
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 10000) { // Reasonable size limit
        return 0;
    }

    // Initialize parser with default config
    yajl_parser_config config = { 1, 1 }; // allowComments=1, checkUTF8=1
    yajl_handle parser = yajl_alloc(&callbacks, &config, NULL, NULL);
    if (!parser) {
        return 0;
    }

    // First parse the provided data
    yajl_status stat = yajl_parse(parser, data, size);
    
    // Then test yajl_parse_complete
    if (stat == yajl_status_ok || stat == yajl_status_insufficient_data) {
        stat = yajl_parse_complete(parser);
    }

    // If there was an error, exercise the error handling code
    if (stat == yajl_status_error) {
        unsigned char *err = yajl_get_error(parser, 1, data, size);
        if (err) {
            yajl_free_error(parser, err);
        }
    }

    yajl_free(parser);
    return 0;
}

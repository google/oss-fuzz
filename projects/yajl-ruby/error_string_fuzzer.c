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

#include "yajl_lex.h"
#include "yajl_parser.h"
#include "yajl_encode.h"
#include "yajl_bytestack.h"
#include "api/yajl_parse.h"

// Helper to create parse error
static void create_parse_error(yajl_handle hand) {
    yajl_bs_push(hand->stateStack, yajl_state_parse_error);
    hand->parseError = "test parse error";
}

// Helper to create lexical error
static void create_lexical_error(yajl_handle hand) {
    yajl_bs_push(hand->stateStack, yajl_state_lexical_error);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Initialize parser
    yajl_parser_config cfg = { 1, 1 }; // allowComments=1, checkUTF8=1
    yajl_handle hand = yajl_alloc(NULL, &cfg, NULL, NULL);
    if (!hand) {
        return 0;
    }

    // Use first byte to determine error type and verbosity
    unsigned int error_type = data[0] % 3; // 0=parse, 1=lexical, 2=other
    int verbose = data[1] & 1;

    // Set bytesConsumed to some position in the input
    hand->bytesConsumed = (size > 2) ? (data[2] % (size - 2)) : 0;

    // Create error state based on type
    switch (error_type) {
        case 0:
            create_parse_error(hand);
            break;
        case 1:
            create_lexical_error(hand);
            break;
        default:
            // Leave in unknown state
            break;
    }

    // Get error string
    unsigned char *error = yajl_render_error_string(hand, 
                                                  data + 2, 
                                                  size > 2 ? size - 2 : 0,
                                                  verbose);

    // Free error string if allocated
    if (error) {
        yajl_free_error(hand, error);
    }

    yajl_free(hand);
    return 0;
}

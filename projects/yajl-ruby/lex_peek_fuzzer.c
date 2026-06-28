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
#include "yajl_alloc.h"
#include "api/yajl_common.h"

// Default allocation functions
static void * malloc_wrapper(void *ctx, unsigned int sz) {
    return malloc(sz);
}

static void * realloc_wrapper(void *ctx, void *ptr, unsigned int sz) {
    return realloc(ptr, sz);
}

static void free_wrapper(void *ctx, void *ptr) {
    free(ptr);
}

static yajl_alloc_funcs allocFuncs = {
    malloc_wrapper,
    realloc_wrapper,
    free_wrapper,
    NULL
};

// Test that peek doesn't affect subsequent lexing
static void test_peek_and_lex(yajl_lexer lexer, const unsigned char* json_text, 
                             size_t json_len, unsigned int offset) {
    const unsigned char *outBuf1, *outBuf2;
    unsigned int outLen1, outLen2;
    unsigned int testOffset = offset;

    // First peek at token
    yajl_tok peek_tok = yajl_lex_peek(lexer, json_text, json_len, offset);
    
    // Now actually lex the token
    yajl_tok lex_tok = yajl_lex_lex(lexer, json_text, json_len, &testOffset,
                                   &outBuf1, &outLen1);
    
    // Verify that peek and actual lex return same token type
    if (peek_tok != lex_tok && peek_tok != yajl_tok_eof) {
        abort(); // Keep the abort to detect inconsistencies
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create lexer with different comment/UTF8 validation combinations
    unsigned int allowComments = data[0] & 1;
    unsigned int validateUTF8 = data[0] & 2;
    
    // Use explicit allocation functions instead of NULL
    yajl_lexer lexer = yajl_lex_alloc(&allocFuncs, allowComments, validateUTF8);
    if (!lexer) {
        return 0;
    }

    const unsigned char *json_text = data + 1;
    size_t json_len = size - 1;
    
    // Test peeking at different offsets through the input
    for (unsigned int offset = 0; offset < json_len; offset++) {
        test_peek_and_lex(lexer, json_text, json_len, offset);
        
        yajl_lexer new_lexer = yajl_lex_realloc(lexer);
        if (!new_lexer) break;
        lexer = new_lexer;
    }

    yajl_lex_free(lexer);
    return 0;
}

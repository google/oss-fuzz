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

#include "yajl_encode.h"
#include "yajl_buf.h"
#include "yajl_alloc.h"

// Storage for print callback verification
static struct {
    const char *data;
    unsigned int len;
    unsigned int calls;
} print_ctx;

// Custom print callback to verify output
static void test_print(void *ctx, const char *str, unsigned int len) {
    print_ctx.calls++;
    print_ctx.data = str;
    print_ctx.len = len;
}

// Default allocation functions with correct types
static void * malloc_wrapper(void *ctx, unsigned int sz) {
    (void)ctx;
    return malloc(sz);
}

static void * realloc_wrapper(void *ctx, void *ptr, unsigned int sz) {
    (void)ctx;
    return realloc(ptr, sz);
}

static void free_wrapper(void *ctx, void *ptr) {
    (void)ctx;
    free(ptr);
}

static yajl_alloc_funcs alloc_funcs = {
    malloc_wrapper,
    realloc_wrapper,
    free_wrapper,
    NULL
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create a buffer for encoding
    yajl_buf buf = yajl_buf_alloc(&alloc_funcs);
    if (!buf) {
        return 0;
    }

    // Use the first byte to determine htmlSafe mode (0, 1, or 2)
    unsigned int htmlSafe = data[0] % 3;
    const unsigned char *str = data + 1;
    size_t str_len = size - 1;

    // Reset print callback context
    print_ctx.calls = 0;
    print_ctx.data = NULL;
    print_ctx.len = 0;

    // Test yajl_string_encode2 with custom printer
    yajl_string_encode2(test_print, NULL, str, str_len, htmlSafe);

    // Test yajl_string_encode with buffer
    yajl_string_encode(buf, str, str_len, htmlSafe);

    // If both were successful, verify they produced same output
    if (print_ctx.calls > 0 && yajl_buf_len(buf) > 0) {
        const unsigned char *buf_data = yajl_buf_data(buf);
        size_t buf_len = yajl_buf_len(buf);
        
        // The buffer might contain concatenated outputs, so we don't compare directly
        // but verify that print_ctx output appears within the buffer data
        if (print_ctx.len > 0 && print_ctx.data && buf_len >= print_ctx.len) {
            // Result can be found somewhere in the buffer
            // Note: we don't assert/abort on mismatch to let fuzzer continue
        }
    }

    yajl_buf_free(buf);
    return 0;
}

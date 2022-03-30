/*
# Copyright 2018 Google Inc.
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

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "api/yajl_parse.h"

typedef struct {
    int arrayLevel;
    int objectLevel;
} context;

static int yajl_found_null(void* ctx) { 
    return 1;
}

static int yajl_found_boolean(void* ctx, int boolean) {
    return 1;
};

static int yajl_found_number(void* ctx, const char* v, unsigned int l) {
    assert(l > 0);
    return 1;
}

static int yajl_found_string(void* ctx, const unsigned char* s, unsigned int l) {
    return 1;
}

static int yajl_found_object_key(void* ctx, const unsigned char* v, unsigned int l) {
    assert(((context*)ctx)->objectLevel > 0);
    return 1;
}

static int yajl_found_start_object(void* ctx) {
    ((context*)ctx)->objectLevel++;
    return 1;
}

static int yajl_found_end_object(void* ctx) {
    assert(((context*)ctx)->objectLevel > 0);
    ((context*)ctx)->objectLevel--;
    return 1;
}

static int yajl_found_start_array(void* ctx) {
    ((context*)ctx)->arrayLevel++;
    return 1;
}

static int yajl_found_end_array(void* ctx) {
    assert(((context*)ctx)->arrayLevel > 0);
    ((context*)ctx)->arrayLevel--;
    return 1;
}

static yajl_callbacks callbacks = {
    yajl_found_null,
    yajl_found_boolean,
    NULL,
    NULL,
    yajl_found_number,
    yajl_found_string,
    yajl_found_start_object,
    yajl_found_object_key,
    yajl_found_end_object,
    yajl_found_start_array,
    yajl_found_end_array
};

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    context ctx = {
        .arrayLevel = 0,
        .objectLevel = 0,
    };
    yajl_parser_config cfg = {
        .allowComments = 1,
        .checkUTF8 = 1,
    };
    yajl_handle parser = yajl_alloc(&callbacks, &cfg, NULL, (void*)&ctx);

    (void)yajl_parse(parser, data, size);
    yajl_free(parser);

    return 0;
}

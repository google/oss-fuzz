/*
 * Copyright 2025 Google LLC
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

/*
 * OSS-Fuzz harness for Redis RESP3 protocol parser (resp_parser.c).
 * Feeds arbitrary bytes as a RESP3 reply stream.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "resp_parser.h"

static void null_cb(void *ctx, const char *proto, size_t proto_len) { (void)ctx; (void)proto; (void)proto_len; }
static void bulk_cb(void *ctx, const char *str, size_t len, const char *proto, size_t proto_len) { (void)ctx; (void)str; (void)len; (void)proto; (void)proto_len; }
static void simple_cb(void *ctx, const char *str, size_t len, const char *proto, size_t proto_len) { (void)ctx; (void)str; (void)len; (void)proto; (void)proto_len; }
static void long_cb(void *ctx, long long val, const char *proto, size_t proto_len) { (void)ctx; (void)val; (void)proto; (void)proto_len; }
static void bool_cb(void *ctx, int val, const char *proto, size_t proto_len) { (void)ctx; (void)val; (void)proto; (void)proto_len; }
static void double_cb(void *ctx, double val, const char *proto, size_t proto_len) { (void)ctx; (void)val; (void)proto; (void)proto_len; }
static void big_num_cb(void *ctx, const char *str, size_t len, const char *proto, size_t proto_len) { (void)ctx; (void)str; (void)len; (void)proto; (void)proto_len; }
static void verbatim_cb(void *ctx, const char *fmt, const char *str, size_t len, const char *proto, size_t proto_len) { (void)ctx; (void)fmt; (void)str; (void)len; (void)proto; (void)proto_len; }
static void array_cb(ReplyParser *parser, void *ctx, size_t len, const char *proto) { (void)parser; (void)ctx; (void)len; (void)proto; }
static void set_cb(ReplyParser *parser, void *ctx, size_t len, const char *proto) { (void)parser; (void)ctx; (void)len; (void)proto; }
static void map_cb(ReplyParser *parser, void *ctx, size_t len, const char *proto) { (void)parser; (void)ctx; (void)len; (void)proto; }
static void attr_cb(ReplyParser *parser, void *ctx, size_t len, const char *proto) { (void)parser; (void)ctx; (void)len; (void)proto; }
static void error_handler(void *ctx) { (void)ctx; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    char *buf = (char *)malloc(size + 2);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\r';
    buf[size + 1] = '\0';

    ReplyParser parser;
    memset(&parser, 0, sizeof(parser));
    parser.curr_location = buf;
    parser.callbacks.null_array_callback = null_cb;
    parser.callbacks.null_bulk_string_callback = null_cb;
    parser.callbacks.bulk_string_callback = bulk_cb;
    parser.callbacks.error_callback = simple_cb;
    parser.callbacks.simple_str_callback = simple_cb;
    parser.callbacks.long_callback = long_cb;
    parser.callbacks.bool_callback = bool_cb;
    parser.callbacks.double_callback = double_cb;
    parser.callbacks.big_number_callback = big_num_cb;
    parser.callbacks.verbatim_string_callback = verbatim_cb;
    parser.callbacks.array_callback = array_cb;
    parser.callbacks.set_callback = set_cb;
    parser.callbacks.map_callback = map_cb;
    parser.callbacks.attribute_callback = attr_cb;
    parser.callbacks.null_callback = null_cb;
    parser.callbacks.error = error_handler;

    parseReply(&parser, NULL);

    free(buf);
    return 0;
}

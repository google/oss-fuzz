/*
 * OSS-Fuzz harness for libuv's URL parser (uv_url_t).
 *
 * libuv provides a URL parsing API used by Node.js's http.IncomingMessage
 * and similar paths to parse request targets and Location headers.
 *
 * Copyright 2024 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "uv.h"

/* uv_url_parse is internal in some versions — include directly */
#include "url-parser/url_parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;

    struct http_parser_url u;
    http_parser_url_init(&u);

    /* is_connect=0: normal URL; is_connect=1: CONNECT target */
    int is_connect = (size > 0 && data[0] & 1) ? 1 : 0;
    const char *input = (const char *) data;

    http_parser_parse_url(input, size, is_connect, &u);

    return 0;
}

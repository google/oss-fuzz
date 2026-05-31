/*
 * OSS-Fuzz harness for Squid's HTTP/1 request-line and header-block parser.
 *
 * Exercises Http::One::RequestParser::parse() with arbitrary input, covering:
 *   - Request-line method, URI, and version parsing
 *   - Header field name and value tokenizing
 *   - Incremental (drip-feed) parsing via repeated parse() calls
 *   - Relaxed vs strict header parsing modes
 *
 * Copyright 2024 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include "squid.h"
#include "http/one/RequestParser.h"
#include "MemBuf.h"
#include "SquidConfig.h"

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    Mem::Init();
    Config.maxRequestHeaderSize = 65536;
    Config.onoff.relaxed_header_parser = 0;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;

    const SBuf input(reinterpret_cast<const char *>(data), size);

    /* Test 1: Full-buffer parse (most common path) */
    {
        Http::One::RequestParser parser;
        parser.parse(input);
    }

    /* Test 2: Byte-at-a-time drip-feed (exercises incremental state machine) */
    if (size <= 512) {
        Http::One::RequestParser parser;
        for (size_t i = 1; i <= size; ++i) {
            SBuf chunk(reinterpret_cast<const char *>(data), i);
            if (parser.parse(chunk) != Http1::HTTP_PARSE_NEED_MORE)
                break;
        }
    }

    /* Test 3: Relaxed parser mode */
    {
        Config.onoff.relaxed_header_parser = 1;
        Http::One::RequestParser parser;
        parser.parse(input);
        Config.onoff.relaxed_header_parser = 0;
    }

    return 0;
}

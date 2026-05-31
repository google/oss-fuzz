/*
 * OSS-Fuzz harness for Squid's HTTP/1 response status-line and header-block parser.
 *
 * Exercises Http::One::ResponseParser::parse() with arbitrary input, covering:
 *   - Status-line parsing (HTTP-version SP status-code SP reason-phrase)
 *   - Header field tokenizing (same code path as request headers)
 *   - Content-Length / Transfer-Encoding conflict detection
 *     (ContentLengthInterpreter is exercised through the header parse path)
 *
 * Copyright 2024 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include "squid.h"
#include "http/one/ResponseParser.h"
#include "MemBuf.h"
#include "SquidConfig.h"

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    Mem::Init();
    Config.maxReplyHeaderSize = 65536;
    Config.onoff.relaxed_header_parser = 0;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;

    const SBuf input(reinterpret_cast<const char *>(data), size);

    /* Test 1: Full-buffer parse */
    {
        Http::One::ResponseParser parser;
        parser.parse(input);
    }

    /* Test 2: Drip-feed (incremental state machine) */
    if (size <= 512) {
        Http::One::ResponseParser parser;
        for (size_t i = 1; i <= size; ++i) {
            SBuf chunk(reinterpret_cast<const char *>(data), i);
            if (parser.parse(chunk) != Http1::HTTP_PARSE_NEED_MORE)
                break;
        }
    }

    return 0;
}

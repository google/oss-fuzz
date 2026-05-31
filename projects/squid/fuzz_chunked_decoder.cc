/*
 * OSS-Fuzz harness for Squid's Transfer-Encoding: chunked body decoder.
 *
 * Exercises Http::One::TeChunkedParser with arbitrary input, covering:
 *   - Chunk-size hex parsing and overflow handling
 *   - Chunk-extension parsing
 *   - Trailer field parsing
 *   - Last-chunk (zero-size) detection
 *   - Incremental byte-at-a-time decoding
 *
 * Copyright 2024 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include "squid.h"
#include "http/one/TeChunkedParser.h"
#include "MemBuf.h"
#include "SquidConfig.h"

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    Mem::Init();
    Config.maxChunkSize = 65536;
    Config.maxRequestHeaderSize = 65536;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;

    const SBuf input(reinterpret_cast<const char *>(data), size);

    /* Test 1: Full-buffer chunked parse */
    {
        MemBuf out;
        out.init(1024, 1024 * 1024);
        Http::One::TeChunkedParser parser;
        parser.setPayloadBuffer(&out);
        parser.parse(input);
        out.clean();
    }

    /* Test 2: Byte-at-a-time (exercises state machine boundaries) */
    if (size <= 256) {
        MemBuf out;
        out.init(1024, 1024 * 1024);
        Http::One::TeChunkedParser parser;
        parser.setPayloadBuffer(&out);
        for (size_t i = 1; i <= size; ++i) {
            SBuf chunk(reinterpret_cast<const char *>(data), i);
            if (parser.parse(chunk) != Http1::HTTP_PARSE_NEED_MORE)
                break;
        }
        out.clean();
    }

    return 0;
}

/*
 * OSS-Fuzz harness for libuv's IDNA (Internationalized Domain Names in
 * Applications) to ASCII encoder — uv__idna_toascii().
 *
 * libuv encodes all hostnames passed to uv_getaddrinfo(), uv_tcp_connect(),
 * and related APIs through this function before sending them to the OS
 * resolver. It implements IDNA 2008 + UTS#46 case-folding and Punycode
 * encoding with a hand-rolled WTF-8 decoder.
 *
 * This path processes attacker-controlled data in Node.js, Deno, and any
 * other runtime built on libuv.
 *
 * Copyright 2024 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* libuv internal header — exposes uv__idna_toascii() */
#include "idna.h"
#include "uv-common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;

    /* uv__idna_toascii expects a null-terminated UTF-8 string */
    char *input = (char *) malloc(size + 1);
    if (!input)
        return 0;
    memcpy(input, data, size);
    input[size] = '\0';

    /* Output buffer: IDNA labels are at most 253 bytes in ASCII */
    char output[256];

    uv__idna_toascii(input, input + size, output, output + sizeof(output));

    free(input);
    return 0;
}

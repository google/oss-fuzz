/*
 * Copyright 2026 Google LLC
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
 * Fuzzer for HAProxy's HTTP/1 message parser (h1_headers_to_hdr_list).
 *
 * This targets the core HTTP/1.1 request and response parsing state machine
 * in src/h1.c, which is HAProxy's primary attack surface: every HTTP/1
 * request from an untrusted client passes through this parser.
 *
 * The parser handles:
 *   - Request line parsing (method, URI, version)
 *   - Response status line parsing
 *   - Header field parsing with folding/continuation
 *   - Transfer-Encoding validation (chunked smuggling detection)
 *   - Content-Length parsing and duplicate detection
 *   - Connection and Upgrade header processing
 *   - HTTP/1.0 vs 1.1 semantics
 *
 * We use the first byte of fuzz input to select between request and
 * response parsing modes, maximizing code coverage.
 */

#include <haproxy/h1.h>
#include <haproxy/http-hdr.h>
#include <haproxy/global.h>

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_HDR_NUM 101

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	struct h1m h1m;
	union h1_sl h1sl;
	struct http_hdr hdrs[MAX_HDR_NUM];
	char *buf;

	if (size < 2)
		return 0;

	/* Use first byte to select request vs response parsing */
	int parse_response = data[0] & 1;
	data++;
	size--;

	/* h1_headers_to_hdr_list modifies the buffer in-place (it writes
	 * the sentinel \0 bytes), so we need a mutable copy. */
	buf = (char *)malloc(size + 1);
	if (!buf)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	/* Ensure global.tune.max_http_hdr is set */
	if (global.tune.max_http_hdr == 0)
		global.tune.max_http_hdr = MAX_HDR_NUM;

	if (parse_response) {
		h1m_init_res(&h1m);
	} else {
		h1m_init_req(&h1m);
	}

	h1_headers_to_hdr_list(buf, buf + size,
	                       hdrs, MAX_HDR_NUM,
	                       &h1m, &h1sl);

	free(buf);
	return 0;
}

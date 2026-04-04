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
 * Fuzzer for HAProxy's HTTP/1-to-HTX conversion pipeline.
 *
 * This targets h1_htx.c which converts raw HTTP/1 wire data into HAProxy's
 * internal HTX (HTTP Transaction) representation. Every HTTP/1 request from
 * an untrusted client passes through this code path:
 *
 *   h1_parse_msg_hdrs()  - parses request/response line + headers into HTX
 *   h1_parse_msg_data()  - parses body (content-length / chunked / EOF)
 *   h1_parse_msg_tlrs()  - parses chunked-encoding trailers
 *
 * This pipeline exercises:
 *   - h1_htx.c  (header post-processing, HTX block construction)
 *   - htx.c     (HTX buffer management, block allocation)
 *   - h1.c      (low-level H1 state machine via h1_headers_to_hdr_list)
 *
 * The first byte of fuzz input selects request vs response mode.
 * The remaining bytes are treated as a raw HTTP/1 message (headers + body).
 */

#include <haproxy/h1.h>
#include <haproxy/h1_htx.h>
#include <haproxy/htx.h>
#include <haproxy/http-hdr.h>
#include <haproxy/global.h>
#include <haproxy/buf.h>

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_HDR_NUM    101
#define HTX_BUF_SIZE   65536
#define TRASH_BUF_SIZE 65536

/* trash is a global scratch buffer used in h1_parse_msg_hdrs (via
 * b_slow_realign_ofs).  Normal startup initialises it, but the fuzzer
 * bypasses the full init sequence. */
extern THREAD_LOCAL struct buffer trash;

static int fuzz_initialized = 0;
static char *htx_area = NULL;
static char *trash_area = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	struct h1m h1m;
	union h1_sl h1sl;
	struct buffer srcbuf;
	struct buffer htxbuf;
	struct htx *htx;
	char *input;
	int ret;
	size_t ofs;

	if (size < 2)
		return 0;

	/* One-time init */
	if (!fuzz_initialized) {
		htx_area = malloc(HTX_BUF_SIZE);
		trash_area = malloc(TRASH_BUF_SIZE);
		if (!htx_area || !trash_area)
			return 0;
		chunk_init(&trash, trash_area, TRASH_BUF_SIZE);
		global.tune.max_http_hdr = MAX_HDR_NUM;
		fuzz_initialized = 1;
	}

	/* First byte: bit 0 selects request vs response */
	int parse_response = data[0] & 1;
	data++;
	size--;

	/* We need a mutable copy for the source buffer.
	 * IMPORTANT: HAProxy uses ring buffers where b_tail wraps around when
	 * data == capacity. We must allocate capacity > data to prevent
	 * b_tail from wrapping to the start (which would give zero-length input
	 * to the parser). */
	input = (char *)malloc(size + 1);
	if (!input)
		return 0;
	memcpy(input, data, size);

	/* Set up source buffer: capacity = size+1 so b_tail doesn't wrap */
	srcbuf = b_make(input, size + 1, 0, size);

	/* Set up destination HTX buffer */
	memset(htx_area, 0, HTX_BUF_SIZE);
	htxbuf = b_make(htx_area, HTX_BUF_SIZE, 0, 0);
	htx = htx_from_buf(&htxbuf);

	/* Initialize the H1 message parser */
	if (parse_response)
		h1m_init_res(&h1m);
	else
		h1m_init_req(&h1m);

	/* Phase 1: Parse headers into HTX */
	ret = h1_parse_msg_hdrs(&h1m, &h1sl, htx, &srcbuf, 0, HTX_BUF_SIZE);

	if (ret > 0) {
		ofs = (size_t)ret;

		/* Phase 2: Parse body data */
		if (ofs < size && h1m.state < H1_MSG_DONE) {
			h1_parse_msg_data(&h1m, &htx, &srcbuf, ofs, HTX_BUF_SIZE, &htxbuf);
		}

		/* Phase 3: Parse trailers (for chunked encoding) */
		if (h1m.state == H1_MSG_TRAILERS) {
			h1_parse_msg_tlrs(&h1m, htx, &srcbuf, ofs, HTX_BUF_SIZE);
		}
	}

	free(input);
	return 0;
}

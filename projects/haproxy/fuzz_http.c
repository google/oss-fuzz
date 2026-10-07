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
 * Fuzzer for HAProxy's HTTP utility functions in src/http.c.
 *
 * This targets the core HTTP semantic parsing functions that process
 * untrusted input from clients and backends:
 *
 *   - URI parsing: http_parse_scheme, http_parse_authority, http_parse_path
 *   - Content-Length: http_parse_cont_len_header (request smuggling surface)
 *   - Cookie parsing: http_extract_cookie_value, http_extract_next_cookie_name
 *   - Header utilities: http_header_match2, http_find_hdr_value_end
 *   - HTTP line parsing: http_parse_header, http_parse_stline,
 *                         http_parse_status_val
 *   - Quality values: http_parse_qvalue
 *   - ETag comparison: http_compare_etags
 *   - Host/port: http_get_host_port, http_is_default_port
 *   - Method lookup: find_http_meth
 *   - Scheme validation: http_validate_scheme
 *   - URL parameters: http_find_next_url_param
 *
 * The first byte of fuzz input selects which function group to exercise,
 * maximizing coverage across the many independent parsers.
 */

#include <haproxy/http.h>
#include <haproxy/http-hdr.h>
#include <haproxy/global.h>

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* Consume one byte from the fuzz data to use as a selector. */
static inline uint8_t fuzz_consume_byte(const uint8_t **data, size_t *size) {
	if (*size == 0)
		return 0;
	uint8_t b = **data;
	(*data)++;
	(*size)--;
	return b;
}

/* Exercise URI parsing: scheme, authority, path */
static void fuzz_uri_parsing(const uint8_t *data, size_t size) {
	char *buf = (char *)malloc(size + 1);
	if (!buf)
		return;
	memcpy(buf, data, size);
	buf[size] = '\0';

	struct ist uri = ist2(buf, size);
	struct http_uri_parser parser = http_uri_parser_init(uri);

	http_parse_scheme(&parser);
	http_parse_authority(&parser, 1);
	http_parse_path(&parser);

	/* Also test with no_userinfo=0 */
	parser = http_uri_parser_init(uri);
	http_parse_scheme(&parser);
	http_parse_authority(&parser, 0);

	free(buf);
}

/* Exercise Content-Length header parsing — critical for request smuggling */
static void fuzz_content_length(const uint8_t *data, size_t size) {
	char *buf = (char *)malloc(size + 1);
	if (!buf)
		return;
	memcpy(buf, data, size);
	buf[size] = '\0';

	struct ist value = ist2(buf, size);
	unsigned long long body_len = 0;

	/* First occurrence */
	int ret = http_parse_cont_len_header(&value, &body_len, 0);

	/* Simulate a second header with same data (duplicate CL detection) */
	if (ret > 0) {
		struct ist value2 = ist2(buf, size);
		http_parse_cont_len_header(&value2, &body_len, 1);
	}

	free(buf);
}

/* Exercise cookie extraction */
static void fuzz_cookie_parsing(const uint8_t *data, size_t size) {
	if (size < 2)
		return;

	char *buf = (char *)malloc(size + 1);
	if (!buf)
		return;
	memcpy(buf, data, size);
	buf[size] = '\0';

	char *hdr = buf;
	const char *hdr_end = buf + size;
	char *value = NULL;
	size_t value_l = 0;

	/* Extract cookie with empty name (match any) */
	http_extract_cookie_value(hdr, hdr_end, "", 0, 1, &value, &value_l);

	/* Extract cookie with a specific 4-byte name from start of input */
	if (size > 6) {
		char name[5];
		memcpy(name, data, 4);
		name[4] = '\0';
		char *search_start = buf + 4;
		http_extract_cookie_value(search_start, hdr_end, name, 4, 1,
		                          &value, &value_l);
	}

	/* Test http_extract_next_cookie_name */
	char *ptr = NULL;
	size_t len = 0;
	http_extract_next_cookie_name(hdr, buf + size, 1, &ptr, &len);
	http_extract_next_cookie_name(hdr, buf + size, 0, &ptr, &len);

	free(buf);
}

/* Exercise header/line parsing utilities */
static void fuzz_header_parsing(const uint8_t *data, size_t size) {
	char *buf = (char *)malloc(size + 1);
	if (!buf)
		return;
	memcpy(buf, data, size);
	buf[size] = '\0';

	struct ist hdr = ist2(buf, size);
	struct ist name, value;

	/* Parse a header line */
	http_parse_header(hdr, &name, &value);

	/* Parse a start line */
	struct ist p1, p2, p3;
	http_parse_stline(hdr, &p1, &p2, &p3);

	/* Parse status value */
	struct ist status, reason;
	http_parse_status_val(hdr, &status, &reason);

	/* header_match2 with a known header name */
	http_header_match2(buf, buf + size, "content-type", 12);
	http_header_match2(buf, buf + size, "host", 4);

	/* find_hdr_value_end */
	http_find_hdr_value_end(buf, buf + size);

	free(buf);
}

/* Exercise host/port, scheme validation, method lookup, qvalue, etags */
static void fuzz_misc(const uint8_t *data, size_t size) {
	char *buf = (char *)malloc(size + 1);
	if (!buf)
		return;
	memcpy(buf, data, size);
	buf[size] = '\0';

	struct ist s = ist2(buf, size);

	/* Host port extraction */
	http_get_host_port(s);

	/* Default port check */
	http_is_default_port(IST_NULL, s);
	http_is_default_port(ist("http://"), s);
	http_is_default_port(ist("https://"), s);

	/* Scheme validation */
	http_validate_scheme(s);

	/* Method lookup */
	find_http_meth(buf, size);

	/* Status index */
	if (size >= 2) {
		unsigned int status = (data[0] << 8) | data[1];
		http_get_status_idx(status);
		http_get_reason(status);
	}

	/* qvalue parsing */
	const char *end = NULL;
	http_parse_qvalue(buf, &end);

	/* ETag comparison: split input in half */
	if (size >= 4) {
		size_t half = size / 2;
		struct ist etag1 = ist2(buf, half);
		struct ist etag2 = ist2(buf + half, size - half);
		http_compare_etags(etag1, etag2);
	}

	/* Trim leading spaces (safe with standalone buffers) */
	http_trim_leading_spht(s);
	/* NOTE: http_trim_trailing_spht is intentionally not fuzzed here because
	 * it reads ret.ptr[-1] which assumes the ist points into the middle of
	 * a larger buffer. Calling it with a standalone allocation would cause
	 * a false-positive heap-buffer-overflow. */

	free(buf);
}

/* Exercise URL parameter finding */
static void fuzz_url_params(const uint8_t *data, size_t size) {
	if (size < 4)
		return;

	char *buf = (char *)malloc(size + 1);
	if (!buf)
		return;
	memcpy(buf, data, size);
	buf[size] = '\0';

	/* Simple single-chunk search */
	const char *chunks[4];
	chunks[0] = buf;
	chunks[1] = buf + size;
	chunks[2] = NULL;
	chunks[3] = NULL;

	const char *vstart = NULL, *vend = NULL;

	/* Search with empty param name (first param) */
	http_find_next_url_param(chunks, "", 0, &vstart, &vend, '&', 0);

	/* Search with a 2-byte param name from start */
	if (size > 4) {
		char pname[3];
		memcpy(pname, data, 2);
		pname[2] = '\0';
		const char *chunks2[4];
		chunks2[0] = buf + 2;
		chunks2[1] = buf + size;
		chunks2[2] = NULL;
		chunks2[3] = NULL;
		http_find_next_url_param(chunks2, pname, 2, &vstart, &vend, '&', 0);

		/* Also try case-insensitive and ';' delimiter */
		http_find_next_url_param(chunks2, pname, 2, &vstart, &vend, ';', 1);
	}

	free(buf);
}

/* Exercise cookie value end finding */
static void fuzz_cookie_value_end(const uint8_t *data, size_t size) {
	char *buf = (char *)malloc(size + 1);
	if (!buf)
		return;
	memcpy(buf, data, size);
	buf[size] = '\0';

	http_find_cookie_value_end(buf, buf + size);

	free(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 2)
		return 0;

	/* Use first byte to select which function group to exercise */
	uint8_t selector = fuzz_consume_byte(&data, &size);

	switch (selector % 7) {
	case 0:
		fuzz_uri_parsing(data, size);
		break;
	case 1:
		fuzz_content_length(data, size);
		break;
	case 2:
		fuzz_cookie_parsing(data, size);
		break;
	case 3:
		fuzz_header_parsing(data, size);
		break;
	case 4:
		fuzz_misc(data, size);
		break;
	case 5:
		fuzz_url_params(data, size);
		break;
	case 6:
		fuzz_cookie_value_end(data, size);
		break;
	}

	return 0;
}

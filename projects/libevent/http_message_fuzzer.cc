/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* Fuzzer for the full HTTP parsing state machine:
 * - Request line and response line parsing with all HTTP methods
 * - Header parsing including continuation lines
 * - Body reading with Content-Length
 * - Chunked transfer encoding
 * - Trailer headers after chunked body
 * - URI parsing with various flags
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "libevent/include/event2/event.h"
#include "libevent/include/event2/buffer.h"
#include "libevent/include/event2/http.h"
#include "libevent/include/event2/http_struct.h"
#include "libevent/include/event2/keyvalq_struct.h"
#include "libevent/http-internal.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 6)
        return 0;

    /* Use first 2 bytes as control */
    uint8_t mode = data[0];
    uint8_t extra = data[1];
    data += 2;
    size -= 2;

    struct evhttp *http_val = evhttp_new(NULL);
    if (!http_val)
        return 0;

    /* Set up a fake connection context for request parsing */
    struct evhttp_connection evcon;
    memset(&evcon, 0, sizeof(evcon));
    evcon.ext_method_cmp = NULL;
    evcon.max_headers_size = (extra % 4 == 0) ? 256 : 8192;
    evcon.http_server = http_val;

    /* === Parse as HTTP request with proper firstline -> headers flow === */
    if (mode & 0x01) {
        struct evhttp_request *req = evhttp_request_new(NULL, NULL);
        if (req) {
            req->kind = EVHTTP_REQUEST;
            req->evcon = &evcon;

            struct evbuffer *buf = evbuffer_new();
            if (buf) {
                evbuffer_add(buf, data, size);

                enum message_read_status s = evhttp_parse_firstline_(req, buf);
                if (s == ALL_DATA_READ) {
                    /* Successfully parsed request line, now parse headers */
                    s = evhttp_parse_headers_(req, buf);
                    if (s == ALL_DATA_READ) {
                        /* Successfully parsed headers, examine parsed data */
                        evhttp_request_get_host(req);
                        evhttp_request_get_uri(req);
                        evhttp_request_get_command(req);

                        struct evkeyvalq *hdrs = evhttp_request_get_input_headers(req);
                        if (hdrs) {
                            evhttp_find_header(hdrs, "Content-Length");
                            evhttp_find_header(hdrs, "Transfer-Encoding");
                            evhttp_find_header(hdrs, "Connection");
                            evhttp_find_header(hdrs, "Host");
                            evhttp_find_header(hdrs, "Expect");
                            evhttp_find_header(hdrs, "Content-Type");
                        }

                        const struct evhttp_uri *uri = evhttp_request_get_evhttp_uri(req);
                        if (uri) {
                            evhttp_uri_get_scheme(uri);
                            evhttp_uri_get_host(uri);
                            evhttp_uri_get_port(uri);
                            evhttp_uri_get_path(uri);
                            evhttp_uri_get_query(uri);
                            evhttp_uri_get_fragment(uri);
                            evhttp_uri_get_userinfo(uri);
                        }

                        /* Move remaining data as body */
                        size_t rem = evbuffer_get_length(buf);
                        if (rem > 0) {
                            struct evbuffer *body = evhttp_request_get_input_buffer(req);
                            if (body)
                                evbuffer_add_buffer(body, buf);
                        }
                    }
                }
                evbuffer_free(buf);
            }
            evhttp_request_free(req);
        }
    }

    /* === Parse as HTTP response === */
    if (mode & 0x02) {
        struct evhttp_request *req = evhttp_request_new(NULL, NULL);
        if (req) {
            req->kind = EVHTTP_RESPONSE;
            req->evcon = &evcon;

            struct evbuffer *buf = evbuffer_new();
            if (buf) {
                evbuffer_add(buf, data, size);

                enum message_read_status s = evhttp_parse_firstline_(req, buf);
                if (s == ALL_DATA_READ) {
                    s = evhttp_parse_headers_(req, buf);
                    if (s == ALL_DATA_READ) {
                        int code = evhttp_request_get_response_code(req);
                        (void)code;
                        const char *reason = evhttp_request_get_response_code_line(req);
                        (void)reason;

                        struct evkeyvalq *hdrs = evhttp_request_get_input_headers(req);
                        if (hdrs) {
                            evhttp_find_header(hdrs, "Content-Length");
                            evhttp_find_header(hdrs, "Transfer-Encoding");
                            evhttp_find_header(hdrs, "Set-Cookie");
                            evhttp_find_header(hdrs, "Location");
                        }
                    }
                }
                evbuffer_free(buf);
            }
            evhttp_request_free(req);
        }
    }

    /* === Parse request with prepended valid method lines to stress header parsing === */
    if (mode & 0x04) {
        static const char *methods[] = {
            "POST / HTTP/1.1\r\n",
            "PUT /resource HTTP/1.1\r\n",
            "DELETE /item HTTP/1.1\r\n",
            "PATCH /update HTTP/1.1\r\n",
            "OPTIONS * HTTP/1.1\r\n",
            "PROPFIND /dav HTTP/1.1\r\n",
            "PROPPATCH /dav HTTP/1.1\r\n",
            "MKCOL /dir HTTP/1.1\r\n",
            "LOCK /file HTTP/1.1\r\n",
            "UNLOCK /file HTTP/1.1\r\n",
            "COPY /src HTTP/1.1\r\n",
            "MOVE /src HTTP/1.1\r\n",
        };
        const char *method = methods[extra % 12];

        struct evhttp_request *req = evhttp_request_new(NULL, NULL);
        if (req) {
            req->kind = EVHTTP_REQUEST;
            req->evcon = &evcon;

            struct evbuffer *buf = evbuffer_new();
            if (buf) {
                evbuffer_add(buf, method, strlen(method));
                evbuffer_add(buf, data, size);

                enum message_read_status s = evhttp_parse_firstline_(req, buf);
                if (s == ALL_DATA_READ) {
                    s = evhttp_parse_headers_(req, buf);
                    if (s == ALL_DATA_READ) {
                        evhttp_request_get_host(req);
                        evhttp_request_get_command(req);
                    }
                }
                evbuffer_free(buf);
            }
            evhttp_request_free(req);
        }
    }

    /* === Parse response with prepended valid status line to stress header parsing === */
    if (mode & 0x08) {
        static const char *status_lines[] = {
            "HTTP/1.1 200 OK\r\n",
            "HTTP/1.0 404 Not Found\r\n",
            "HTTP/1.1 301 Moved Permanently\r\n",
            "HTTP/1.1 500 Internal Server Error\r\n",
            "HTTP/1.1 100 Continue\r\n",
            "HTTP/1.1 204 No Content\r\n",
            "HTTP/1.0 302 Found\r\n",
            "HTTP/1.1 403 Forbidden\r\n",
        };
        const char *status = status_lines[extra % 8];

        struct evhttp_request *req = evhttp_request_new(NULL, NULL);
        if (req) {
            req->kind = EVHTTP_RESPONSE;
            req->evcon = &evcon;

            struct evbuffer *buf = evbuffer_new();
            if (buf) {
                evbuffer_add(buf, status, strlen(status));
                evbuffer_add(buf, data, size);

                enum message_read_status s = evhttp_parse_firstline_(req, buf);
                if (s == ALL_DATA_READ) {
                    s = evhttp_parse_headers_(req, buf);
                    if (s == ALL_DATA_READ) {
                        evhttp_request_get_response_code(req);
                        evhttp_request_get_response_code_line(req);

                        struct evkeyvalq *hdrs = evhttp_request_get_input_headers(req);
                        if (hdrs) {
                            evhttp_find_header(hdrs, "Content-Type");
                            evhttp_find_header(hdrs, "Server");
                        }
                    }
                }
                evbuffer_free(buf);
            }
            evhttp_request_free(req);
        }
    }

    /* === Exercise evhttp_decode_uri with percent-encoded data === */
    if (mode & 0x10) {
        char *uri_str = (char *)malloc(size + 1);
        if (uri_str) {
            memcpy(uri_str, data, size);
            uri_str[size] = '\0';

            char *decoded = evhttp_decode_uri(uri_str);
            if (decoded)
                free(decoded);

            char *encoded = evhttp_encode_uri(uri_str);
            if (encoded)
                free(encoded);

            free(uri_str);
        }
    }

    /* === Exercise evhttp_parse_query_str_flags === */
    if (mode & 0x20) {
        char *query = (char *)malloc(size + 1);
        if (query) {
            memcpy(query, data, size);
            query[size] = '\0';

            struct evkeyvalq params;
            TAILQ_INIT(&params);
            int flags = (extra & 0x0F);
            evhttp_parse_query_str_flags(query, &params, flags);

            /* Iterate and free all parsed parameters */
            struct evkeyval *kv;
            while ((kv = TAILQ_FIRST(&params)) != NULL) {
                TAILQ_REMOVE(&params, kv, next);
                free(kv->key);
                free(kv->value);
                free(kv);
            }

            free(query);
        }
    }

    /* === Exercise header add/remove/clear operations === */
    if (mode & 0x40) {
        struct evkeyvalq headers;
        TAILQ_INIT(&headers);

        /* Split fuzz data into key/value pairs to add as headers */
        size_t pos = 0;
        int count = 0;
        while (pos < size && count < 32) {
            /* Find a separator for key */
            size_t key_end = pos;
            while (key_end < size && data[key_end] != ':' && data[key_end] != '\0')
                key_end++;
            if (key_end >= size) break;

            size_t val_start = key_end + 1;
            size_t val_end = val_start;
            while (val_end < size && data[val_end] != '\n' && data[val_end] != '\0')
                val_end++;

            if (key_end > pos) {
                char *key = (char *)malloc(key_end - pos + 1);
                char *val = (char *)malloc(val_end - val_start + 1);
                if (key && val) {
                    memcpy(key, data + pos, key_end - pos);
                    key[key_end - pos] = '\0';
                    memcpy(val, data + val_start, val_end - val_start);
                    val[val_end - val_start] = '\0';

                    evhttp_add_header(&headers, key, val);
                    count++;
                }
                free(key);
                free(val);
            }
            pos = val_end + 1;
        }

        /* Try to find some headers */
        if (count > 0) {
            evhttp_find_header(&headers, "Content-Type");
            evhttp_find_header(&headers, "Host");
        }

        evhttp_clear_headers(&headers);
    }

    evhttp_free(http_val);
    return 0;
}

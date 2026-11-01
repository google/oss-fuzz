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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "first.h"
#include "buffer.h"
#include "array.h"
#include "http_header.h"
#include "request.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 65536) {
        return 0;
    }

    const int scheme_port = (data[0] & 1u) ? 443 : 80;
    const unsigned int parseopts = (unsigned int)data[0] >> 1;
    ++data; --size;

    char *hdrs = (char *)malloc(size + 1);
    if (NULL == hdrs) return 0;
    memcpy(hdrs, data, size);
    hdrs[size] = '\0';

    /* h1.c seeds hoff with the line count and the base offset */
    unsigned short *hoff = (unsigned short *)malloc(8192 * sizeof(unsigned short));
    if (NULL == hoff) { free(hdrs); return 0; }
    hoff[0] = 1;
    hoff[1] = 0;

    const uint32_t hlen = http_header_parse_hoff(hdrs, (uint32_t)size, hoff);

    if (0 != hlen && hoff[0] < 8192 - 1) {
        request_st r;
        memset(&r, 0, sizeof(request_st));
        r.conf.http_parseopts = parseopts;
        r.conf.max_request_field_size = 8192;
        r.http_method = HTTP_METHOD_UNSET;
        r.http_version = HTTP_VERSION_UNSET;
        r.server_name = &r.uri.authority;
        /* request_init_data() takes this from srv->tmp_buf */
        buffer * const tmp_buf = buffer_init();
        r.tmp_buf = tmp_buf;

        http_request_headers_process(&r, hdrs, hoff, scheme_port);

        buffer_free(tmp_buf);
        array_free_data(&r.rqst_headers);
        buffer_free_ptr(&r.target);
        buffer_free_ptr(&r.target_orig);
        buffer_free_ptr(&r.uri.scheme);
        buffer_free_ptr(&r.uri.authority);
        buffer_free_ptr(&r.uri.path);
        buffer_free_ptr(&r.uri.query);
        buffer_free_ptr(&r.pathinfo);
        buffer_free_ptr(&r.physical.path);
        buffer_free_ptr(&r.physical.basedir);
        buffer_free_ptr(&r.physical.doc_root);
        buffer_free_ptr(&r.physical.rel_path);
    }

    free(hoff);
    free(hdrs);
    return 0;
}

// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "event2/buffer.h"
#include "event2/tag.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4)
        return 0;

    // Use first 2 bytes as control for which operations to perform
    uint8_t ops = data[0];
    uint8_t need_tag_byte = data[1];
    data += 2;
    size -= 2;

    struct evbuffer *buf = evbuffer_new();
    if (!buf)
        return 0;

    evbuffer_add(buf, data, size);

    // Exercise evtag_peek
    ev_uint32_t tag_val = 0;
    evtag_peek(buf, &tag_val);

    // Exercise evtag_peek_length
    ev_uint32_t total_len = 0;
    evtag_peek_length(buf, &total_len);

    // Exercise evtag_payload_length
    ev_uint32_t payload_len = 0;
    evtag_payload_length(buf, &payload_len);

    // Try evtag_unmarshal into a destination buffer
    if (ops & 0x01) {
        struct evbuffer *dst = evbuffer_new();
        if (dst) {
            struct evbuffer *tmp = evbuffer_new();
            if (tmp) {
                evbuffer_add(tmp, data, size);
                ev_uint32_t unmarshal_tag = 0;
                evtag_unmarshal(tmp, &unmarshal_tag, dst);
                evbuffer_free(tmp);
            }
            evbuffer_free(dst);
        }
    }

    // Try evtag_unmarshal_int
    if (ops & 0x02) {
        struct evbuffer *tmp = evbuffer_new();
        if (tmp) {
            evbuffer_add(tmp, data, size);
            ev_uint32_t int_val = 0;
            ev_uint32_t need_tag = (ev_uint32_t)need_tag_byte;
            evtag_unmarshal_int(tmp, need_tag, &int_val);
            evbuffer_free(tmp);
        }
    }

    // Try evtag_unmarshal_int64
    if (ops & 0x04) {
        struct evbuffer *tmp = evbuffer_new();
        if (tmp) {
            evbuffer_add(tmp, data, size);
            ev_uint64_t int64_val = 0;
            ev_uint32_t need_tag = (ev_uint32_t)need_tag_byte;
            evtag_unmarshal_int64(tmp, need_tag, &int64_val);
            evbuffer_free(tmp);
        }
    }

    // Try evtag_unmarshal_string
    if (ops & 0x08) {
        struct evbuffer *tmp = evbuffer_new();
        if (tmp) {
            evbuffer_add(tmp, data, size);
            char *str = nullptr;
            ev_uint32_t need_tag = (ev_uint32_t)need_tag_byte;
            if (evtag_unmarshal_string(tmp, need_tag, &str) == 0 && str) {
                std::free(str);
            }
            evbuffer_free(tmp);
        }
    }

    // Try evtag_unmarshal_timeval
    if (ops & 0x10) {
        struct evbuffer *tmp = evbuffer_new();
        if (tmp) {
            evbuffer_add(tmp, data, size);
            struct timeval tv;
            ev_uint32_t need_tag = (ev_uint32_t)need_tag_byte;
            evtag_unmarshal_timeval(tmp, need_tag, &tv);
            evbuffer_free(tmp);
        }
    }

    // Try evtag_unmarshal_fixed
    if (ops & 0x20) {
        struct evbuffer *tmp = evbuffer_new();
        if (tmp) {
            evbuffer_add(tmp, data, size);
            char fixed_buf[64];
            ev_uint32_t need_tag = (ev_uint32_t)need_tag_byte;
            size_t fixed_len = (size < sizeof(fixed_buf)) ? size : sizeof(fixed_buf);
            evtag_unmarshal_fixed(tmp, need_tag, fixed_buf, fixed_len);
            evbuffer_free(tmp);
        }
    }

    // Try evtag_consume
    if (ops & 0x40) {
        struct evbuffer *tmp = evbuffer_new();
        if (tmp) {
            evbuffer_add(tmp, data, size);
            evtag_consume(tmp);
            evbuffer_free(tmp);
        }
    }

    // Try evtag_unmarshal_header
    if (ops & 0x80) {
        struct evbuffer *tmp = evbuffer_new();
        if (tmp) {
            evbuffer_add(tmp, data, size);
            ev_uint32_t hdr_tag = 0;
            evtag_unmarshal_header(tmp, &hdr_tag);
            evbuffer_free(tmp);
        }
    }

    // Marshal then unmarshal round-trip with fuzz data
    if (size >= 4) {
        struct evbuffer *rt_buf = evbuffer_new();
        if (rt_buf) {
            ev_uint32_t rt_tag;
            memcpy(&rt_tag, data, 4);
            evtag_marshal(rt_buf, rt_tag, data + 4, size - 4);

            struct evbuffer *rt_dst = evbuffer_new();
            if (rt_dst) {
                ev_uint32_t out_tag = 0;
                evtag_unmarshal(rt_buf, &out_tag, rt_dst);
                evbuffer_free(rt_dst);
            }
            evbuffer_free(rt_buf);
        }
    }

    // Exercise marshal_string + unmarshal_string round trip
    if (size > 1) {
        struct evbuffer *str_buf = evbuffer_new();
        if (str_buf) {
            // Null-terminate a copy of the data for marshal_string
            char *str_data = (char *)std::malloc(size + 1);
            if (str_data) {
                memcpy(str_data, data, size);
                str_data[size] = '\0';
                ev_uint32_t str_tag = (ev_uint32_t)need_tag_byte;
                evtag_marshal_string(str_buf, str_tag, str_data);

                // Try to unmarshal it back
                char *out_str = nullptr;
                if (evtag_unmarshal_string(str_buf, str_tag, &out_str) == 0 && out_str) {
                    std::free(out_str);
                }
                std::free(str_data);
            }
            evbuffer_free(str_buf);
        }
    }

    // Exercise marshal_int + unmarshal_int round trip
    if (size >= 4) {
        struct evbuffer *int_buf = evbuffer_new();
        if (int_buf) {
            ev_uint32_t int_tag = (ev_uint32_t)need_tag_byte;
            ev_uint32_t int_val;
            memcpy(&int_val, data, 4);
            evtag_marshal_int(int_buf, int_tag, int_val);

            ev_uint32_t out_val = 0;
            evtag_unmarshal_int(int_buf, int_tag, &out_val);
            evbuffer_free(int_buf);
        }
    }

    // Exercise marshal_int64 + unmarshal_int64 round trip
    if (size >= 8) {
        struct evbuffer *int64_buf = evbuffer_new();
        if (int64_buf) {
            ev_uint32_t int64_tag = (ev_uint32_t)need_tag_byte;
            ev_uint64_t int64_val;
            memcpy(&int64_val, data, 8);
            evtag_marshal_int64(int64_buf, int64_tag, int64_val);

            ev_uint64_t out_val64 = 0;
            evtag_unmarshal_int64(int64_buf, int64_tag, &out_val64);
            evbuffer_free(int64_buf);
        }
    }

    // Exercise marshal_buffer
    if (size > 0) {
        struct evbuffer *src_buf = evbuffer_new();
        struct evbuffer *marsh_buf = evbuffer_new();
        if (src_buf && marsh_buf) {
            evbuffer_add(src_buf, data, size);
            ev_uint32_t buf_tag = (ev_uint32_t)need_tag_byte;
            evtag_marshal_buffer(marsh_buf, buf_tag, src_buf);

            // Unmarshal it
            struct evbuffer *out_buf = evbuffer_new();
            if (out_buf) {
                ev_uint32_t out_tag = 0;
                evtag_unmarshal(marsh_buf, &out_tag, out_buf);
                evbuffer_free(out_buf);
            }
        }
        if (src_buf) evbuffer_free(src_buf);
        if (marsh_buf) evbuffer_free(marsh_buf);
    }

    evbuffer_free(buf);
    return 0;
}

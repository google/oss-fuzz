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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

extern "C" {
#include "event2/event.h"
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/http.h"
#include "event2/http_struct.h"
#include "event2/ws.h"
#include "http-internal.h"
}

static void on_msg(struct evws_connection *ws, int type, const uint8_t *data, size_t len, void *arg) {
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct event_base *base = event_base_new();
    if (!base) return 0;

    struct evhttp *http = evhttp_new(base);
    struct bufferevent *bev[2];
    if (bufferevent_pair_new(base, 0, bev) != 0) {
        evhttp_free(http);
        event_base_free(base);
        return 0;
    }

    struct evhttp_connection *evcon = evhttp_connection_base_bufferevent_new(base, NULL, bev[0], "127.0.0.1", 80);
    
    /* Associate evcon with http to satisfy evws_new_session requirements */
    evcon->http_server = http;
    TAILQ_INSERT_TAIL(&http->connections, evcon, next);

    struct evhttp_request *req = evhttp_request_new(NULL, NULL);
    if (!req) {
        evhttp_connection_free(evcon);
        evhttp_free(http);
        bufferevent_free(bev[1]);
        return 0;
    }
    req->evcon = evcon;
    req->kind = EVHTTP_REQUEST;
    TAILQ_INSERT_TAIL(&evcon->requests, req, next);

    /* Add required headers for WebSocket handshake */
    struct evkeyvalq *in_hdrs = evhttp_request_get_input_headers(req);
    evhttp_add_header(in_hdrs, "Upgrade", "websocket");
    evhttp_add_header(in_hdrs, "Connection", "Upgrade");
    evhttp_add_header(in_hdrs, "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

    /* evws_new_session takes 4 arguments in this version of libevent */
    struct evws_connection *ws = evws_new_session(req, on_msg, NULL, 0);
    if (ws) {
        struct evbuffer *output = bufferevent_get_output(bev[1]);
        evbuffer_add(output, data, size);
        
        event_base_loop(base, EVLOOP_NONBLOCK);
        
        evws_connection_free(ws);
    }
    evhttp_free(http);
    bufferevent_free(bev[1]);
    event_base_free(base);

    return 0;
}

/* Copyright 2022 Google LLC
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

/*
 * Uses the Honggfuzz netdriver logic:
 * - https://github.com/google/honggfuzz/tree/master/libhfnetdriver
 * This fuzzer can only be compiled with Honggfuzz (and not libFuzzer of AFL).
 */
#include "libevent/include/event2/buffer.h"
#include "libevent/include/event2/event.h"
#include "libevent/include/event2/http.h"

static void handle_request(struct evhttp_request *req, void *arg)
{
    const char *uri = evhttp_request_get_uri(req);
    struct evbuffer *buf = evbuffer_new();
    evbuffer_add_printf(buf, "From fuzzer cb, %s!", uri);
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

HFND_FUZZING_ENTRY_FUNCTION(int argc, char **argv) {
    struct event_base *base = event_base_new();
    struct evhttp *http = evhttp_new(base);
    evhttp_bind_socket(http, "0.0.0.0", 8666);
    evhttp_set_gencb(http, handle_request, NULL);
    event_base_dispatch(base);
    return 0;
}

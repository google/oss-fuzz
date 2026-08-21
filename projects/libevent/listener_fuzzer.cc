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
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

extern "C" {
#include "event2/event.h"
#include "event2/listener.h"
#include "event2/util.h"
}

static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *address, int socklen, void *arg) {
    evutil_closesocket(fd);
}

static void error_cb(struct evconnlistener *lev, void *arg) {
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    struct event_base *base = event_base_new();
    if (!base) return 0;

    uint32_t flags_raw = *(uint32_t*)data;
    unsigned flags = 0;
    if (flags_raw & 0x01) flags |= LEV_OPT_LEAVE_SOCKETS_BLOCKING;
    if (flags_raw & 0x02) flags |= LEV_OPT_CLOSE_ON_FREE;
    if (flags_raw & 0x04) flags |= LEV_OPT_CLOSE_ON_EXEC;
    if (flags_raw & 0x08) flags |= LEV_OPT_REUSEABLE;
    if (flags_raw & 0x10) flags |= LEV_OPT_THREADSAFE;
    if (flags_raw & 0x20) flags |= LEV_OPT_DISABLED;
    if (flags_raw & 0x40) flags |= LEV_OPT_DEFERRED_ACCEPT;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;

    struct evconnlistener *lev = evconnlistener_new_bind(base, accept_cb, NULL,
        flags, -1, (struct sockaddr*)&sin, sizeof(sin));
    
    if (lev) {
        evconnlistener_set_error_cb(lev, error_cb);

        if (flags & LEV_OPT_DISABLED) {
            evconnlistener_enable(lev);
        }

        // Get the port we bound to
        evutil_socket_t listen_fd = evconnlistener_get_fd(lev);
        struct sockaddr_in bound_sin;
        socklen_t bound_sin_len = sizeof(bound_sin);
        if (getsockname(listen_fd, (struct sockaddr*)&bound_sin, &bound_sin_len) == 0) {
            // Connect to it
            int client_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (client_fd >= 0) {
                evutil_make_socket_nonblocking(client_fd);
                if (connect(client_fd, (struct sockaddr*)&bound_sin, bound_sin_len) < 0) {
                    if (errno != EINPROGRESS) {
                        // ignore
                    }
                }
                
                // Run loop to process the acceptance
                event_base_loop(base, EVLOOP_NONBLOCK);
                
                close(client_fd);
            }
        }
        evconnlistener_free(lev);
    }

    event_base_free(base);

    return 0;
}

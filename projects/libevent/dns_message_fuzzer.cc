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
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "event2/event.h"
#include "event2/dns.h"

// Callback for DNS server - just respond to every request and drop it
static void dns_server_cb(struct evdns_server_request *req, void *data) {
    // Respond with NOERROR to exercise the response path too
    evdns_server_request_respond(req, 0);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12 || size > 1500)
        return 0;

    // Create a UDP socketpair
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) < 0)
        return 0;

    struct event_base *base = event_base_new();
    if (!base) {
        close(fds[0]);
        close(fds[1]);
        return 0;
    }

    // Create DNS server port on fds[0]
    struct evdns_server_port *port =
        evdns_add_server_port_with_base(base, fds[0], 0, dns_server_cb, nullptr);
    if (!port) {
        event_base_free(base);
        close(fds[0]);
        close(fds[1]);
        return 0;
    }

    // Send the fuzz data as a DNS packet to the server via fds[1]
    send(fds[1], data, size, 0);

    // Run the event loop briefly to process the packet
    event_base_loop(base, EVLOOP_NONBLOCK);

    // Clean up
    evdns_close_server_port(port);
    event_base_free(base);
    close(fds[0]);
    close(fds[1]);

    return 0;
}

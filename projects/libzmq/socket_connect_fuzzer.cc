// Copyright 2020 Luca Boccassi <bluca@debian.org>
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

#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <assert.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "include/zmq.h"

// Test that the ZMTP engine handles invalid handshake when connecting
// https://rfc.zeromq.org/spec/37/
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    void *client, *ctx;
    struct sockaddr_in ip4addr;
    socklen_t ip4addr_len = sizeof(ip4addr);
    char endpoint[32];
    size_t sent_bytes;
    int server, server_accept, rc;

    ip4addr.sin_family = AF_INET;
    ip4addr.sin_port = 0;
    inet_pton(AF_INET, "127.0.0.1", &ip4addr.sin_addr);
    server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(server >= 0);
    rc = bind(server, reinterpret_cast<struct sockaddr *> (&ip4addr), sizeof(ip4addr));
    assert(rc >= 0);
    rc = listen (server, SOMAXCONN);
    assert(rc == 0);
    rc = getsockname (server, (struct sockaddr *) &ip4addr, &ip4addr_len);
    assert(rc == 0);
    sprintf(endpoint, "tcp://127.0.0.1:%u", ntohs(ip4addr.sin_port));

    ctx = zmq_ctx_new ();
    assert(ctx);
    client = zmq_socket(ctx, ZMQ_SUB);
    assert(client);
    rc = zmq_connect(client, endpoint);
    assert(rc == 0);

    // Send as many bytes as possible, and then let the background I/O thread
    // have some time to handle them.
    // We should at least be able to send 33 bytes, which is the very first
    // part of the ZMTP 3.x handshake. Otherwise something is not quite right
    // in the localhost connection we set up.
    server_accept = accept(server, NULL, NULL);
    sent_bytes = write(server_accept, (const char *)data, size);
    assert(size < 33 || sent_bytes >= 33);
    usleep (static_cast<useconds_t> (250) * 1000);

    close(server_accept);
    close(server);

    rc = zmq_close(client);
    assert(rc == 0);
    rc = zmq_ctx_term(ctx);
    assert(rc == 0);

    return 0;
}

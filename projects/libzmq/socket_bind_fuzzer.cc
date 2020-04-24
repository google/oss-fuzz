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

#include "include/zmq.h"

// Test that the ZMTP engine handles invalid handshake when binding
// https://rfc.zeromq.org/spec/37/
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    void *server, *ctx;
    struct sockaddr_in ip4addr;
    char endpoint[32];
    size_t endpoint_len = 32, sent_bytes;
    unsigned short port;
    int client, rc, linger = 0;

    ctx = zmq_ctx_new ();
    assert(ctx);
    server = zmq_socket(ctx, ZMQ_PUB);
    assert(server);
    rc = zmq_setsockopt (server, ZMQ_LINGER, &linger, sizeof(linger));
    assert(rc == 0);
    rc = zmq_bind(server, "tcp://127.0.0.1:*");
    assert(rc == 0);
    rc = zmq_getsockopt(server, ZMQ_LAST_ENDPOINT, endpoint, &endpoint_len);
    assert(rc == 0);
    rc = sscanf(endpoint, "tcp://127.0.0.1:%hu", &port);
    assert(rc == 1);

    ip4addr.sin_family = AF_INET;
    ip4addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &ip4addr.sin_addr);
    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(client >= 0);
    rc = connect(client, reinterpret_cast<struct sockaddr *> (&ip4addr), sizeof(ip4addr));
    assert(rc >= 0);

    // Send as many bytes as possible, and then let the background I/O thread
    // have some time to handle them.
    // We should at least be able to send 33 bytes, which is the very first
    // part of the ZMTP 3.x handshake. Otherwise something is not quite right
    // in the localhost connection we set up.
    sent_bytes = write(client, (const char *)data, size);
    assert(size < 33 || sent_bytes >= 33);
    usleep (static_cast<useconds_t> (250) * 1000);

    close(client);

    rc = zmq_close(server);
    assert(rc == 0);
    rc = zmq_ctx_term(ctx);
    assert(rc == 0);

    return 0;
}

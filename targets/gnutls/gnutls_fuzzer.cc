/*
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <gnutls/gnutls.h>


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int res;
    gnutls_session_t session;

    int socket_fds[2];
    res = socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds);
    assert(res >= 0);
    ssize_t send_res = send(socket_fds[1], data, size, 0);
    assert(send_res == size);

    res = gnutls_init(&session, GNUTLS_CLIENT);
    assert(res >= 0);

    res = gnutls_set_default_priority(session);
    assert(res >= 0);

    gnutls_transport_set_int(session, socket_fds[0]);

    do {
        res = gnutls_handshake(session);
    } while (res < 0 && gnutls_error_is_fatal(res) == 0);
    if (res >= 0) {
        while (true) {
            char buf[16384];
            res = gnutls_record_recv(session, buf, sizeof(buf));
            if (res <= 0) {
                break;
            }
        }
    }

    close(out_fd);
    close(socket_fds[0]);
    close(socket_fds[1]);
    gnutls_deinit(session);
    return 0;
}

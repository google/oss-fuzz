# Copyright 2021 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y pkg-config make autoconf automake libtool libssl-dev liblzo2-dev libpam-dev libnl-3-dev libnl-genl-3-dev libcap-ng-dev

RUN git clone --depth 1 https://github.com/google/boringssl.git boringssl
RUN git clone --depth 1 https://github.com/OpenVPN/openvpn openvpn
WORKDIR openvpn
RUN sed -i 's/read(/fuzz_read(/g' src/openvpn/console_systemd.c && \
    sed -i 's/fgets(/fuzz_fgets(/g' src/openvpn/console_builtin.c && \
    sed -i 's/fgets(/fuzz_fgets(/g' src/openvpn/misc.c && \
    sed -i 's/#include "forward.h"/#include "fuzz_header.h"\n#include "forward.h"/g' src/openvpn/proxy.c && \
    sed -i 's/openvpn_select(/fuzz_select(/g' src/openvpn/proxy.c && \
    sed -i 's/openvpn_send(/fuzz_send(/g' src/openvpn/proxy.c && \
    sed -i 's/recv(/fuzz_recv(/g' src/openvpn/proxy.c && \
    sed -i 's/isatty/fuzz_isatty/g' src/openvpn/console_builtin.c && \
    sed -i 's/fopen/fuzz_fopen/g' src/openvpn/console_builtin.c && \
    sed -i 's/fclose/fuzz_fclose/g' src/openvpn/console_builtin.c && \
    sed -i 's/sendto/fuzz_sendto/g' src/openvpn/socket.h && \
    sed -i 's/#include "misc.h"/#include "misc.h"\nextern size_t fuzz_sendto(int sockfd, void *buf, size_t len, int flags, struct sockaddr *dest_addr, socklen_t addrlen);/g' src/openvpn/socket.h && \
    sed -i 's/fp = (flags/fp = stdout;\n\/\//g' src/openvpn/error.c && \
    sed -i 's/crypto_msg(M_FATAL/crypto_msg(M_WARN/g' src/openvpn/crypto_openssl.c && \
    sed -i 's/msg(M_FATAL, \"Cipher/return;msg(M_FATAL, \"Cipher/g' src/openvpn/crypto.c && \
    sed -i 's/msg(M_FATAL/msg(M_WARN/g' src/openvpn/crypto.c && \
    sed -i 's/= write/= fuzz_write/g' src/openvpn/packet_id.c

COPY build.sh $SRC/
COPY fuzz*.cpp $SRC/
COPY fuzz*.c $SRC/
COPY fuzz*.h $SRC/openvpn/src/openvpn/

COPY crypto_patch.txt $SRC/crypto_patch.txt

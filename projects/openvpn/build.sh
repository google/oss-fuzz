#!/bin/bash -eu
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

# Changes in the code so we can fuzz it.
git apply $SRC/crypto_patch.txt

echo "" >> $SRC/openvpn/src/openvpn/openvpn.c
echo "ssize_t fuzz_get_random_data(void *buf, size_t len) { return 0; }" >> $SRC/openvpn/src/openvpn/fake_fuzz_header.h
echo "int fuzz_success;" >> $SRC/openvpn/src/openvpn/fake_fuzz_header.h
echo "#include \"fake_fuzz_header.h\"" >> $SRC/openvpn/src/openvpn/openvpn.c

sed -i 's/read(/fuzz_read(/g' ./src/openvpn/console_systemd.c
sed -i 's/fgets(/fuzz_fgets(/g' ./src/openvpn/console_builtin.c
sed -i 's/fgets(/fuzz_fgets(/g' ./src/openvpn/misc.c
sed -i 's/#include "forward.h"/#include "fuzz_header.h"\n#include "forward.h"/g' ./src/openvpn/proxy.c
sed -i 's/select(/fuzz_select(/g' ./src/openvpn/proxy.c
sed -i 's/send(/fuzz_send(/g' ./src/openvpn/proxy.c
sed -i 's/recv(/fuzz_recv(/g' ./src/openvpn/proxy.c

sed -i 's/fopen/fuzz_fopen/g' ./src/openvpn/console_builtin.c
sed -i 's/fclose/fuzz_fclose/g' ./src/openvpn/console_builtin.c

sed -i 's/sendto/fuzz_sendto/g' ./src/openvpn/socket.h
sed -i 's/#include "misc.h"/#include "misc.h"\nextern size_t fuzz_sendto(int sockfd, void *buf, size_t len, int flags, struct sockaddr *dest_addr, socklen_t addrlen);/g' ./src/openvpn/socket.h

sed -i 's/fp = (flags/fp = stdout;\n\/\//g' ./src/openvpn/error.c

sed -i 's/crypto_msg(M_FATAL/crypto_msg(M_WARN/g' ./src/openvpn/crypto_openssl.c
sed -i 's/msg(M_FATAL, \"Cipher/return;msg(M_FATAL, \"Cipher/g' ./src/openvpn/crypto.c
sed -i 's/msg(M_FATAL/msg(M_WARN/g' ./src/openvpn/crypto.c

sed -i 's/= write/= fuzz_write/g' ./src/openvpn/packet_id.c

# Copy corpuses out
zip -r $OUT/fuzz_verify_cert_seed_corpus.zip $SRC/boringssl/fuzz/cert_corpus

# Build openvpn
autoreconf -ivf
./configure --disable-lz4 --with-crypto-library=openssl OPENSSL_LIBS="-L/usr/local/ssl/ -lssl -lcrypto" OPENSSL_CFLAGS="-I/usr/local/ssl/include/"
make

# Make openvpn object files into a library we can link fuzzers to
cd src/openvpn
rm openvpn.o
ar r libopenvpn.a *.o

# Compile our fuzz helper
$CXX $CXXFLAGS -g -c $SRC/fuzz_randomizer.cpp -o $SRC/fuzz_randomizer.o

# Compile the fuzzers
for fuzzname in fuzz_dhcp fuzz_misc fuzz_base64 fuzz_proxy fuzz_buffer fuzz_route fuzz_packet_id fuzz_mroute fuzz_list fuzz_verify_cert fuzz_forward fuzz_crypto; do
    $CC -DHAVE_CONFIG_H -I. -I../.. -I../../include  -I../../include -I../../src/compat \
      -DPLUGIN_LIBDIR=\"/usr/local/lib/openvpn/plugins\"  -Wall -std=c99 $CFLAGS \
      -c $SRC/${fuzzname}.c -o $SRC/${fuzzname}.o

    # Link with CXX
    $CXX ${CXXFLAGS} ${LIB_FUZZING_ENGINE} $SRC/${fuzzname}.o -o $OUT/${fuzzname} $SRC/fuzz_randomizer.o \
        libopenvpn.a ../../src/compat/.libs/libcompat.a /usr/lib/x86_64-linux-gnu/libnsl.a \
        /usr/lib/x86_64-linux-gnu/libresolv.a /usr/lib/x86_64-linux-gnu/liblzo2.a \
        -lssl -lcrypto -ldl
done

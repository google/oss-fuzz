#!/bin/bash -eux
# Copyright 2026 Google LLC
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

cd $SRC/openvpn

# Bootstrap autotools
autoreconf -fvi

# Configure OpenVPN — build the core library objects
./configure \
    --disable-plugin-auth-pam \
    --disable-plugin-down-root \
    CC="$CC" \
    CFLAGS="$CFLAGS -DENABLE_CRYPTO_OPENSSL=1" \
    LDFLAGS="$LIB_FUZZING_ENGINE"

# Build all .o files
make -j$(nproc) -C src/openvpn

# Collect all .o files (excluding main.o to avoid duplicate main())
OPENVPN_OBJS=$(find src/openvpn -name "*.o" ! -name "openvpn.o" | tr '\n' ' ')

CFLAGS_ALL="$CFLAGS -I$SRC/openvpn -I$SRC/openvpn/src/openvpn -I$SRC/openvpn/src/compat"

# Build fuzz_options
$CC $CFLAGS_ALL -o $OUT/fuzz_options \
    $SRC/fuzz_options.c $OPENVPN_OBJS $LIB_FUZZING_ENGINE \
    -lssl -lcrypto -llzo2 -llz4 -lpthread

# Build fuzz_tls_pre_decrypt
$CC $CFLAGS_ALL -o $OUT/fuzz_tls_pre_decrypt \
    $SRC/fuzz_tls_pre_decrypt.c $OPENVPN_OBJS $LIB_FUZZING_ENGINE \
    -lssl -lcrypto -llzo2 -llz4 -lpthread

# Seed corpus for fuzz_options — typical OpenVPN config lines
OPTIONS_SEED="$OUT/fuzz_options_seed_corpus.zip"
mkdir -p /tmp/options_seed
echo 'remote vpn.example.com 1194 udp' > /tmp/options_seed/remote.txt
echo 'cipher AES-256-GCM' > /tmp/options_seed/cipher.txt
echo 'push "route 10.0.0.0 255.255.255.0"' > /tmp/options_seed/push.txt
echo 'ifconfig 10.8.0.1 10.8.0.2' > /tmp/options_seed/ifconfig.txt
echo 'proto tcp-client' > /tmp/options_seed/proto.txt
zip -j "$OPTIONS_SEED" /tmp/options_seed/*.txt

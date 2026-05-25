#!/bin/bash -eu
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
#
################################################################################

# Build wolfSSL with wolfTPM support enabled. We install statically into a
# local prefix so we don't depend on system headers/libs.
PREFIX="$WORK/wolfssl-install"
mkdir -p "$PREFIX"

cd "$SRC/wolfssl"
./autogen.sh
./configure \
    --prefix="$PREFIX" \
    --enable-static --disable-shared \
    --enable-wolftpm \
    --enable-pkcallbacks \
    --enable-keygen \
    --enable-certgen \
    --enable-certreq \
    --enable-certext \
    CFLAGS="$CFLAGS -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP"
make -j$(nproc)
make install

export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"

# Build wolfTPM (static lib only).
cd "$SRC/wolfTPM"
./autogen.sh
./configure \
    --prefix="$WORK/wolftpm-install" \
    --enable-static --disable-shared \
    --disable-examples \
    --disable-wrapper \
    CFLAGS="$CFLAGS -I$PREFIX/include" \
    LDFLAGS="-L$PREFIX/lib"
make -j$(nproc)

# Build the fuzz harness, linking wolftpm + wolfssl statically.
$CC $CFLAGS \
    -I"$SRC/wolfTPM" \
    -I"$PREFIX/include" \
    -c "$SRC/ada-fuzzers/projects/wolftpm/fuzzer/fuzz_asn_cert.c" -o "$WORK/fuzz_asn_cert.o"

$CXX $CXXFLAGS \
    "$WORK/fuzz_asn_cert.o" \
    "$SRC/wolfTPM/src/.libs/libwolftpm.a" \
    "$PREFIX/lib/libwolfssl.a" \
    $LIB_FUZZING_ENGINE \
    -o "$OUT/fuzz_asn_cert"

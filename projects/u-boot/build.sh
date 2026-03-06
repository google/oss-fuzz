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

MBEDTLS=$SRC/u-boot/lib/mbedtls/external/mbedtls

# Build mbedtls static libraries with fuzzing instrumentation
make -C $MBEDTLS/library -j$(nproc)

cd $WORK

# Build each standalone mbedtls fuzzer
for fuzzer in fuzz_pubkey fuzz_x509crt fuzz_x509crl fuzz_x509csr fuzz_pkcs7; do
    $CC $CFLAGS -I$MBEDTLS/include \
        -c $MBEDTLS/programs/fuzz/${fuzzer}.c -o ${fuzzer}.o
    $CXX $CXXFLAGS ${fuzzer}.o \
        -L$MBEDTLS/library -lmbedtls -lmbedx509 -lmbedcrypto \
        $LIB_FUZZING_ENGINE -o $OUT/mbedtls_${fuzzer}
    rm ${fuzzer}.o
done

# Build mbedtls fuzzers that need common.c
$CC $CFLAGS -I$MBEDTLS/include \
    -c $MBEDTLS/programs/fuzz/common.c -o common.o
for fuzzer in fuzz_privkey; do
    $CC $CFLAGS -I$MBEDTLS/include \
        -c $MBEDTLS/programs/fuzz/${fuzzer}.c -o ${fuzzer}.o
    $CXX $CXXFLAGS ${fuzzer}.o common.o \
        -L$MBEDTLS/library -lmbedtls -lmbedx509 -lmbedcrypto \
        $LIB_FUZZING_ENGINE -o $OUT/mbedtls_${fuzzer}
    rm ${fuzzer}.o
done

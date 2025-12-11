#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# Build Nettle with mini-gmp (no external gmp dependency)
cd $SRC/nettle
bash .bootstrap

if [[ $CFLAGS != *sanitize=memory* ]]
then
    ./configure --enable-mini-gmp --disable-documentation --disable-openssl --prefix=$SRC/nettle-install
else
    ./configure --enable-mini-gmp --disable-documentation --disable-openssl --disable-assembler --prefix=$SRC/nettle-install
fi

make -j$(nproc)
make install

# Build all fuzzers
FUZZERS="
fuzz_dsa_sha1_keypair_from_sexp
fuzz_dsa_sha256_keypair_from_sexp
fuzz_dsa_signature_from_sexp
fuzz_dsa_openssl_private_key_from_der
fuzz_rsa_keypair_from_sexp
fuzz_rsa_keypair_from_der
fuzz_rsa_public_key_from_der
"

for fuzzer in $FUZZERS; do
    $CC $CFLAGS -I$SRC/nettle-install/include -c $SRC/${fuzzer}.c -o $SRC/${fuzzer}.o
    $CXX $CXXFLAGS $SRC/${fuzzer}.o -o $OUT/${fuzzer} \
        $LIB_FUZZING_ENGINE \
        $SRC/nettle-install/lib/libhogweed.a \
        $SRC/nettle-install/lib/libnettle.a
done


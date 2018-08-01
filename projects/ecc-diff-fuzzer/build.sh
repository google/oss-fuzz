#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# build projects
#mbedtls
(
cd mbedtls
cmake . -DENABLE_PROGRAMS=0 -DENABLE_TESTING=0
make -j$(nproc) all
)

#openssl
(
cd openssl
./config
make build_generated libcrypto.a
)

#libecc
(
cd libecc
#required by libecc
(export CFLAGS="$CFLAGS -fPIC"; make)
echo $CFLAGS
)

#build fuzz target
cd ecfuzzer
cp fuzz_ec.dict $OUT/
$CC $CFLAGS -I. -c fuzz_ec.c -o fuzz_ec.o
$CC $CFLAGS -I. -I../mbedtls/include -c modules/mbedtls.c -o mbedtls.o
$CC $CFLAGS -I. -I../openssl/include -c modules/openssl.c -o openssl.o
$CC $CFLAGS -DWITH_STDLIB -I. -I../libecc/src -c modules/libecc.c -o libecc.o

$CXX $CXXFLAGS fuzz_ec.o mbedtls.o libecc.o openssl.o -o $OUT/fuzz_ec ../mbedtls/library/libmbedcrypto.a ../libecc/build/libec.a ../openssl/libcrypto.a -lFuzzingEngine

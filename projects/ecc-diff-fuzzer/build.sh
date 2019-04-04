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
#nettle
(
cd nettle
tar -xvf ../gmp-6.1.2.tar.bz2
cd gmp-6.1.2
#do not use assembly instructions as we do not know if they will be available on the machine who will run the fuzzer
#we could do instead --enable-fat
./configure --disable-assembly
make
make install
cd ..
autoreconf
./configure
make
)

#cryptopp
(
cd cryptopp
make
)

#gcrypt
(
cd gcrypt
tar -xvf ../libgpg-error-1.32.tar.bz2
cd libgpg-error-1.32
./configure --enable-static --disable-shared
make
make install
cd ..
./autogen.sh
./configure --enable-static --disable-shared --disable-doc --enable-maintainer-mode
make
)

#mbedtls
(
cd mbedtls
cmake . -DENABLE_PROGRAMS=0 -DENABLE_TESTING=0
make -j$(nproc) all
)

#openssl
(
cd openssl
#option to not have the same exported function poly1305_blocks as in gcrypt
./config no-poly1305 no-shared no-threads
make build_generated libcrypto.a
)

#libecc
(
cd libecc
#required by libecc
(export CFLAGS="$CFLAGS -fPIC"; make)
)

#build fuzz target
cd ecfuzzer
zip -r fuzz_ec_seed_corpus.zip corpus/
cp fuzz_ec_seed_corpus.zip $OUT/
cp fuzz_ec.dict $OUT/

$CC $CFLAGS -I. -c fuzz_ec.c -o fuzz_ec.o
$CC $CFLAGS -I. -I../mbedtls/include -c modules/mbedtls.c -o mbedtls.o
$CC $CFLAGS -I. -I../openssl/include -c modules/openssl.c -o openssl.o
$CC $CFLAGS -DWITH_STDLIB -I. -I../libecc/src -c modules/libecc.c -o libecc.o
$CC $CFLAGS -I. -I../gcrypt/src -c modules/gcrypt.c -o gcrypt.o
$CXX $CXXFLAGS -I. -I../ -c modules/cryptopp.cpp -o cryptopp.o
$CC $CFLAGS -I. -I../ -c modules/nettle.c -o nettle.o

$CXX $CXXFLAGS fuzz_ec.o mbedtls.o libecc.o openssl.o gcrypt.o cryptopp.o nettle.o -o $OUT/fuzz_ec ../mbedtls/library/libmbedcrypto.a ../libecc/build/libec.a ../libecc/src/external_deps/rand.o ../openssl/libcrypto.a ../nettle/libhogweed.a ../nettle/libnettle.a ../nettle/gmp-6.1.2/.libs/libgmp.a ../gcrypt/src/.libs/libgcrypt.a ../cryptopp/libcryptopp.a -lgpg-error $LIB_FUZZING_ENGINE

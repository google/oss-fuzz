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
cd libgpg-error
./autogen.sh
if [ "$ARCHITECTURE" = 'i386' ]; then
    ./configure -host=i386 --disable-doc --enable-static --disable-shared
else
    ./configure --disable-doc --enable-static --disable-shared
fi
make
make install
cd ../gcrypt
./autogen.sh
if [ "$ARCHITECTURE" = 'i386' ]; then
    ./configure -host=i386 --enable-static --disable-shared --disable-doc --enable-maintainer-mode --disable-asm
else
    ./configure --enable-static --disable-shared --disable-doc --enable-maintainer-mode --disable-asm
fi
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
if [ "$ARCHITECTURE" = 'i386' ]; then
    setarch i386 ./config no-poly1305 no-shared no-threads -m32
else
    ./config no-poly1305 no-shared no-threads
fi
make build_generated libcrypto.a
)

#libecc
(
cd libecc
#required by libecc
(export CFLAGS="$CFLAGS -fPIC"; make)
)

#botan
(
cd botan
#help it find libstdc++
cp /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /usr/lib/x86_64-linux-gnu/libstdc++.so
export LDFLAGS=$CXXFLAGS
if [ "$ARCHITECTURE" = 'i386' ]; then
    ./configure.py --disable-shared-library --cpu x86_32
else
    ./configure.py --disable-shared-library
fi
make
)

#build fuzz target
cd ecfuzzer
zip -r fuzz_ec_seed_corpus.zip corpus/
cp fuzz_ec_seed_corpus.zip $OUT/
cp fuzz_ec.dict $OUT/

$CC $CFLAGS -I. -c fuzz_ec.c -o fuzz_ec.o
$CC $CFLAGS -I. -c fail.c -o fail.o
$CC $CFLAGS -I. -I../mbedtls/include -I../mbedtls/crypto/include -c modules/mbedtls.c -o mbedtls.o
$CC $CFLAGS -I. -I../openssl/include -c modules/openssl.c -o openssl.o
$CC $CFLAGS -DWITH_STDLIB -I. -I../libecc/src -c modules/libecc.c -o libecc.o
$CC $CFLAGS -I. -I../gcrypt/src -c modules/gcrypt.c -o gcrypt.o
$CXX $CXXFLAGS -I. -I../ -c modules/cryptopp.cpp -o cryptopp.o
$CC $CFLAGS -I. -I../ -c modules/nettle.c -o nettle.o
$CXX $CXXFLAGS -std=c++11 -I. -I../ -I../botan/build/include -c modules/botan.cpp -o botan.o

$CXX $CXXFLAGS fuzz_ec.o fail.o mbedtls.o libecc.o openssl.o gcrypt.o cryptopp.o nettle.o botan.o -o $OUT/fuzz_ec ../mbedtls/crypto/library/libmbedcrypto.a ../libecc/build/libec.a ../libecc/src/external_deps/rand.o ../openssl/libcrypto.a ../nettle/libhogweed.a ../nettle/libnettle.a ../nettle/gmp-6.1.2/.libs/libgmp.a ../gcrypt/src/.libs/libgcrypt.a ../cryptopp/libcryptopp.a ../botan/libbotan-2.a -lgpg-error $LIB_FUZZING_ENGINE

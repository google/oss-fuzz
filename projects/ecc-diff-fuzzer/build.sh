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

# use a linker that supports Dwarf v5
export LDFLAGS="-fuse-ld=lld"

# build projects
#nettle
(
cd nettle
tar -xvf ../gmp-6.2.1.tar.bz2
cd gmp-6.2.1
#do not use assembly instructions as we do not know if they will be available on the machine who will run the fuzzer
#we could do instead --enable-fat
./configure --disable-shared --disable-assembly
make -j$(nproc)
make install
cd ..
autoreconf
./configure --disable-shared --disable-openssl
make -j$(nproc)
make install
)

#cryptopp
(
cd cryptopp
make -j$(nproc)
make install
)

#gcrypt
(
cd libgpg-error
# fix for following error
# error: gettext infrastructure mismatch: using a Makefile.in.in from gettext version 0.19 but the autoconf macros are from gettext version 0.20
timeout 3 gettextize -f || true
./autogen.sh
if [ "$ARCHITECTURE" = 'i386' ]; then
    ./configure -host=i386 --disable-doc --enable-static --disable-shared
else
    ./configure --disable-doc --enable-static --disable-shared
fi
make -j$(nproc)
make install
cd ../gcrypt
./autogen.sh
if [ "$ARCHITECTURE" = 'i386' ]; then
    ./configure -host=i386 --enable-static --disable-shared --disable-doc --enable-maintainer-mode
else
    ./configure --enable-static --disable-shared --disable-doc --enable-maintainer-mode
fi
make -j$(nproc)
make install
# defined at aria.o:(aria_encrypt) in archive /lib/x86_64-linux-gnu/libcrypto.a
sed -i -e s/aria_encrypt/ariagencrypt/ /usr/local/lib/libgcrypt.a
)

#mbedtls
(
cd mbedtls
cmake . -DENABLE_PROGRAMS=0 -DENABLE_TESTING=0
make -j$(nproc) all
make install
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
make install
)

#libecc
(
cd libecc
#required by libecc
(export CFLAGS="$CFLAGS -fPIC"; make; cp build/*.a /usr/local/lib; cp -r src/* /usr/local/include/)
)

#botan
(
cd botan
if [ "$ARCHITECTURE" = 'i386' ]; then
    ./configure.py --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" \
               --disable-shared --disable-modules=locking_allocator --disable-shared-library \
               --without-os-features=getrandom,getentropy --cpu x86_32
else
    ./configure.py --cc-bin=$CXX --cc-abi-flags="$CXXFLAGS" \
               --disable-shared --disable-modules=locking_allocator --disable-shared-library \
               --without-os-features=getrandom,getentropy
fi
make -j$(nproc)
make install
)

#quickjs
(
cd quickjs
if [ "$ARCHITECTURE" = 'i386' ]; then
    make qjsc
    cp qjsc /usr/local/bin/
    make clean
    # Makefile should not override CFLAGS
    sed -i -e 's/CFLAGS=/CFLAGS+=/' Makefile
    CFLAGS="-m32" make libquickjs.a
else
    make && make install
fi
cp quickjs*.h /usr/local/include/
cp libquickjs.a /usr/local/lib/
)

export CARGO_BUILD_TARGET="x86_64-unknown-linux-gnu"
#build fuzz target
cd ecfuzzer
if [ "$ARCHITECTURE" = 'i386' ]; then
    export GOARCH=386
#needed explicitly because of cross compilation cf https://golang.org/cmd/cgo/
    export CGO_ENABLED=1
    export CARGO_BUILD_TARGET=i686-unknown-linux-gnu
fi
zip -r fuzz_ec_seed_corpus.zip corpus/
cp fuzz_ec_seed_corpus.zip $OUT/
cp fuzz_ec.dict $OUT/
cp fuzz_ec.dict $OUT/fuzz_ec_noblocker.dict

mkdir build
cd build
#no afl with long javascript initialization
if [ "$FUZZING_ENGINE" != 'afl' ]; then
    cmake ..
    make -j$(nproc)
    cp ecfuzzer $OUT/fuzz_ec
    rm -Rf *
fi

#another target without javascript
cmake -DDISABLE_JS=ON ..
make -j$(nproc)
cp ecfuzzer $OUT/fuzz_ec_noblocker

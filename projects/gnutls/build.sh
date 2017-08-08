#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

CONFIGURE_FLAGS=""
NETTLE_CONFIGURE_FLAGS=""
if [[ $CFLAGS = *sanitize=memory* ]]
then
  CONFIGURE_FLAGS="--disable-hardware-acceleration"
  NETTLE_CONFIGURE_FLAGS="--disable-assembler --disable-fat"
fi

# We could use GMP from git repository to avoid false positives in
# sanitizers, but GMP doesn't compile with clang. We use gmp-mini
# instead.

pushd nettle
bash .bootstrap
./configure --enable-mini-gmp --disable-documentation --libdir=/opt/lib/ --prefix=/opt $NETTLE_CONFIGURE_FLAGS && ( make -j$(nproc) || make -j$(nproc) ) && make install
if test $? != 0;then
	echo "Failed to compile nettle"
	exit 1
fi
popd

make bootstrap
PKG_CONFIG_PATH=/opt/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig ./configure --with-nettle-mini --enable-gcc-warnings --enable-static --with-included-libtasn1 \
    --with-included-unistring --without-p11-kit --disable-doc $CONFIGURE_FLAGS

# Do not use the syscall interface for randomness in oss-fuzz, it seems
# to confuse memory sanitizer.
sed -i 's|include <sys/syscall.h>|include <sys/syscall.h>\n#undef SYS_getrandom|' lib/nettle/sysrng-linux.c

make "-j$(nproc)" -C gl
make "-j$(nproc)" -C lib

fuzzers=$(find devel/fuzz/ -name "*_fuzzer.cc")

for f in $fuzzers; do
    fuzzer=$(basename "$f" ".cc")
    $CXX $CXXFLAGS -std=c++11 -Ilib/includes \
        "devel/fuzz/${fuzzer}.cc" -o "$OUT/${fuzzer}" \
        lib/.libs/libgnutls.a -lFuzzingEngine -lpthread -Wl,-Bstatic \
        /opt/lib/libhogweed.a /opt/lib/libnettle.a -Wl,-Bdynamic

    corpus_dir=$(basename "${fuzzer}" "_fuzzer")
    if [ -d "devel/fuzz/${corpus_dir}.in/" ]; then
        zip -r "$OUT/${fuzzer}_seed_corpus.zip" "devel/fuzz/${corpus_dir}.in/"
    fi
done

#!/bin/bash -eu
#
# Copyright 2019 Google Inc.
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

if [ "$SANITIZER" = undefined ]; then
    export CFLAGS="$CFLAGS -fsanitize=integer -fno-sanitize-recover=integer"
    export CXXFLAGS="$CXXFLAGS -fsanitize=integer -fno-sanitize-recover=integer"
fi

if [ "$SANITIZER" = memory ]; then
    # This would require an instrumented libgcrypt build.
    CRYPTO_CONF=--without-crypto
    CRYPTO_LIBS=
else
    CRYPTO_CONF=--with-crypto
    CRYPTO_LIBS=-lgcrypt
fi

cd ../libxml2
./autogen.sh \
    --disable-shared \
    --without-c14n \
    --without-push \
    --without-python \
    --without-reader \
    --without-regexps \
    --without-sax1 \
    --without-schemas \
    --without-schematron \
    --without-valid \
    --without-writer \
    --without-zlib \
    --without-lzma
make -j$(nproc) V=1

cd ../libxslt
./autogen.sh \
    --with-libxml-src=../libxml2 \
    --disable-shared \
    --without-python \
    $CRYPTO_CONF \
    --without-debug \
    --without-debugger \
    --without-profiler
make -j$(nproc) V=1

cd tests/fuzz
rm -rf seed
make fuzz.o

for fuzzer in xpath xslt; do
    make $fuzzer.o
    # Link with $CXX
    $CXX $CXXFLAGS \
        $fuzzer.o fuzz.o \
        -o $OUT/$fuzzer \
        $LIB_FUZZING_ENGINE \
        ../../libexslt/.libs/libexslt.a ../../libxslt/.libs/libxslt.a \
        ../../../libxml2/.libs/libxml2.a \
        $CRYPTO_LIBS

    [ -e seed/$fuzzer ] || make seed/$fuzzer.stamp
    zip -j $OUT/${fuzzer}_seed_corpus.zip seed/$fuzzer/*
done

cp *.dict $OUT/

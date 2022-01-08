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
    export CFLAGS="$CFLAGS -fsanitize=unsigned-integer-overflow -fno-sanitize-recover=unsigned-integer-overflow"
    export CXXFLAGS="$CXXFLAGS -fsanitize=unsigned-integer-overflow -fno-sanitize-recover=unsigned-integer-overflow"
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
    --without-legacy \
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

for file in xpath xslt fuzz; do
    # Compile as C
    $CC $CFLAGS \
        -I. -I../libxml2/include \
        -c tests/fuzz/$file.c \
        -o tests/fuzz/$file.o
done

for fuzzer in xpath xslt; do
    # Link with $CXX
    $CXX $CXXFLAGS \
        tests/fuzz/$fuzzer.o tests/fuzz/fuzz.o \
        -o $OUT/$fuzzer \
        $LIB_FUZZING_ENGINE \
        libexslt/.libs/libexslt.a libxslt/.libs/libxslt.a \
        ../libxml2/.libs/libxml2.a \
        $CRYPTO_LIBS

    zip -j $OUT/${fuzzer}_seed_corpus.zip tests/fuzz/seed/$fuzzer/*
done

cp tests/fuzz/*.dict tests/fuzz/*.xml $OUT/

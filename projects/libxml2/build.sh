#!/bin/bash -eu
#
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

if [ "$SANITIZER" = undefined ]; then
    export CFLAGS="$CFLAGS -fsanitize=unsigned-integer-overflow -fno-sanitize-recover=unsigned-integer-overflow"
    export CXXFLAGS="$CXXFLAGS -fsanitize=unsigned-integer-overflow -fno-sanitize-recover=unsigned-integer-overflow"
fi

./autogen.sh \
    --disable-shared \
    --without-ftp \
    --without-http \
    --without-legacy \
    --without-python
make -j$(nproc) V=1
make -C fuzz V=1 seed/schema.stamp seed/xml.stamp fuzz.o
cp -r test/HTML fuzz/seed/html

for fuzzer in html schema xml; do
    make -C fuzz $fuzzer.o
    # Link with $CXX
    $CXX $CXXFLAGS \
        fuzz/$fuzzer.o fuzz/fuzz.o \
        -o $OUT/$fuzzer \
        $LIB_FUZZING_ENGINE \
        .libs/libxml2.a -Wl,-Bstatic -lz -llzma -Wl,-Bdynamic

    zip -j $OUT/${fuzzer}_seed_corpus.zip fuzz/seed/$fuzzer/*
done

cp fuzz/*.dict fuzz/*.options $OUT/

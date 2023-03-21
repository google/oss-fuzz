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
    export CFLAGS="$CFLAGS -fsanitize=integer -fno-sanitize-recover=integer"
    export CXXFLAGS="$CXXFLAGS -fsanitize=integer -fno-sanitize-recover=integer"
fi

export V=1

./autogen.sh \
    --disable-shared \
    --without-debug \
    --without-http \
    --without-python
make -j$(nproc)

cd fuzz
make clean-corpus
make fuzz.o

for fuzzer in html regexp schema uri valid xinclude xml xpath; do
    make $fuzzer.o
    # Link with $CXX
    $CXX $CXXFLAGS \
        $fuzzer.o fuzz.o \
        -o $OUT/$fuzzer \
        $LIB_FUZZING_ENGINE \
        ../.libs/libxml2.a -Wl,-Bstatic -lz -llzma -Wl,-Bdynamic

    [ -e seed/$fuzzer ] || make seed/$fuzzer.stamp
    zip -j $OUT/${fuzzer}_seed_corpus.zip seed/$fuzzer/*
done

cp *.dict *.options $OUT/

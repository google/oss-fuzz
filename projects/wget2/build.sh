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

! test -d lib && ./bootstrap
! test -f config.h && ./configure --enable-static --disable-doc
make -j$(nproc)

find fuzz -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
find fuzz -name '*_fuzzer.options' -exec cp -v '{}' $OUT ';'

fuzzers=$(find fuzz -name "*_fuzzer.cc")

for f in $fuzzers; do
    fuzzer=$(basename "$f" ".cc")

    $CXX $CXXFLAGS -std=c++11 -Iinclude/wget/ \
        "fuzz/${fuzzer}.cc" -o "$OUT/${fuzzer}" \
        libwget/.libs/libwget.a -lFuzzingEngine -Wl,-Bstatic \
        -lidn2 -lunistring \
        -Wl,-Bdynamic

    if [ -f "$SRC/${fuzzer}_seed_corpus.zip" ]; then
        cp "$SRC/${fuzzer}_seed_corpus.zip" "$OUT/"
    fi

    if [ -d "fuzz/${fuzzer}.in/" ]; then
        zip -rj "$OUT/${fuzzer}_seed_corpus.zip" "fuzz/${fuzzer}.in/"
    fi
done

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
if [[ $CFLAGS = "*sanitize=memory*" ]]
then
  CONFIGURE_FLAGS="--disable-hardware-acceleration"
fi

make bootstrap
./configure --enable-gcc-warnings --enable-static --with-included-libtasn1 \
    --with-included-unistring --without-p11-kit --disable-doc $CONFIGURE_FLAGS
make "-j$(nproc)"

fuzzers=$(find devel/fuzz/ -name "*_fuzzer.cc")

for f in $fuzzers; do
    fuzzer=$(basename "$f" ".cc")
    $CXX $CXXFLAGS -std=c++11 -Ilib/includes \
        "devel/fuzz/${fuzzer}.cc" -o "$OUT/${fuzzer}" \
        lib/.libs/libgnutls.a -lFuzzingEngine -lpthread -Wl,-Bstatic \
        -lhogweed -lnettle -lgmp -Wl,-Bdynamic

    if [ -f "$SRC/${fuzzer}_seed_corpus.zip" ]; then
        cp "$SRC/${fuzzer}_seed_corpus.zip" "$OUT/"
    fi

    corpus_dir=$(basename "${fuzzer}" "_fuzzer")
    if [ -d "devel/fuzz/${corpus_dir}.in/" ]; then
        zip -r "$OUT/${fuzzer}_seed_corpus.zip" "devel/fuzz/${corpus_dir}.in/"
    fi
done

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
##############################################################################

cd ${SRC}/tor

sh autogen.sh

# We need to run configure with leak-checking disabled, or many of the
# test functions will fail.
export ASAN_OPTIONS=detect_leaks=0

./configure --disable-asciidoc --enable-oss-fuzz --disable-memory-sentinels
make clean
make -j$(nproc) oss-fuzz-fuzzers

TORLIBS="src/or/libtor-testing.a"
TORLIBS="$TORLIBS src/common/libor-crypto-testing.a"
TORLIBS="$TORLIBS src/ext/keccak-tiny/libkeccak-tiny.a"
TORLIBS="$TORLIBS src/common/libcurve25519_donna.a"
TORLIBS="$TORLIBS src/ext/ed25519/ref10/libed25519_ref10.a"
TORLIBS="$TORLIBS src/ext/ed25519/donna/libed25519_donna.a"
TORLIBS="$TORLIBS src/common/libor-testing.a"
TORLIBS="$TORLIBS src/common/libor-ctime-testing.a"
TORLIBS="$TORLIBS src/common/libor-event-testing.a"
TORLIBS="$TORLIBS src/trunnel/libor-trunnel-testing.a"
TORLIBS="$TORLIBS -lm -Wl,-Bstatic -lssl -lcrypto -levent -lz -Wl,-Bdynamic"

for fuzzer in src/test/fuzz/*.a; do
    output="${fuzzer%.a}"
    output="${output##*lib}"
    ${CXX} ${CXXFLAGS} -std=c++11 -lFuzzingEngine ${fuzzer} ${TORLIBS} -o ${OUT}/${output}
    zip -j ${OUT}/${output}_seed_corpus.zip ${SRC}/tor-fuzz-corpora/${output#oss-fuzz-}/*
done



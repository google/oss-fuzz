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

cmake -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
      -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      -DMSGPACK_CXX11=ON .
make -j$(nproc) all

for f in $SRC/msgpack-c/fuzz/*_fuzzer.cpp; do
    fuzzer=$(basename "$f" _fuzzer.cpp)
    $CXX $CXXFLAGS -std=c++11 -Iinclude -I"$SRC/msgpack-c/include" \
         "$f" -o "$OUT/${fuzzer}_fuzzer" \
         -lFuzzingEngine "$SRC/msgpack-c/libmsgpackc.a"
done

zip -rj "$OUT/unpack_pack_fuzzer_seed_corpus.zip" "$SRC/msgpack-corpora/packed/"

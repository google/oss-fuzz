#!/bin/bash -eu
# Copyright 2026 Google LLC.
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

cd $SRC/nanomq

mkdir -p build && cd build

cmake \
  -G Ninja \
  -DENABLE_FUZZING=ON \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DLIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" \
  ..

ninja pub_decode_fuzzer

# Copy fuzzer binary
cp nanomq/tests/fuzz/pub_decode_fuzzer $OUT/

# Copy dictionary (named <binary>.dict for automatic pickup)
cp $SRC/nanomq/nanomq/tests/fuzz/mqtt.dict $OUT/pub_decode_fuzzer.dict

# Package seed corpus (named <binary>_seed_corpus.zip)
zip -j $OUT/pub_decode_fuzzer_seed_corpus.zip \
    $SRC/nanomq/nanomq/tests/fuzz/corpus/*

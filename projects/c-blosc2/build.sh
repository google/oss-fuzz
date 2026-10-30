#!/bin/bash -eu
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

# Build project
export LDSHARED=lld

# Build with fuzzer and unit test
cmake . -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
        -DBUILD_FUZZERS=ON -DBUILD_TESTS=ON -DBUILD_BENCHMARKS=OFF \
        -DBUILD_EXAMPLES=OFF -DBUILD_STATIC=ON -DBUILD_SHARED=OFF
make clean
make -j$(nproc)

# Package seed corpus
zip -j $OUT/decompress_chunk_fuzzer_seed_corpus.zip compat/*.cdata
zip -j $OUT/decompress_frame_fuzzer_seed_corpus.zip tests/fuzz/corpus/*

# Copy the fuzzer executables, zip-ed corpora, and dictionary files to $OUT
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer_seed_corpus.zip' -exec cp -v '{}' $OUT ';'

# Build the b2nd seed-corpus generator and prepare options file 
$CC $CFLAGS -I$SRC/c-blosc2/include -o $SRC/c-blosc2/gen_b2nd_corpus \
    $SRC/c-blosc2/tests/fuzz/gen_b2nd_corpus.c \
    $SRC/c-blosc2/blosc/libblosc2.a -lpthread -lm -ldl
mkdir -p $SRC/b2nd_corpus
ASAN_OPTIONS=detect_leaks=0 $SRC/c-blosc2/gen_b2nd_corpus $SRC/b2nd_corpus
zip -j -q $OUT/b2nd_fuzzer_seed_corpus.zip $SRC/b2nd_corpus/*

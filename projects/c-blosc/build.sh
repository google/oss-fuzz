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
cmake . -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS"     \
        -DBUILD_FUZZERS=ON -DBUILD_TESTS=ON -DBUILD_BENCHMARKS=OFF \
        -DBUILD_STATIC=ON -DBUILD_SHARED=ON
make clean
make -j$(nproc)

# Package seed corpus
zip -j $OUT/decompress_fuzzer_seed_corpus.zip compat/*.cdata

# Copy the fuzzer executables, zip-ed corpora, and dictionary files to $OUT
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer_seed_corpus.zip' -exec cp -v '{}' $OUT ';'

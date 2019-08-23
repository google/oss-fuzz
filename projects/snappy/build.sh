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

# build project and fuzzers
mkdir -p build
cd build
export SNAPPY_FUZZING_FLAGS=""
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Debug -DSNAPPY_REQUIRE_AVX=ON \
    -DSNAPPY_OSSFUZZ_BUILD=ON -DSNAPPY_BUILD_TESTS=OFF
cmake --build .

# Copy fuzzer to $OUT
cp *_fuzzer $OUT

# Create zip file for compress/decompress fuzzers
# Note that both fuzzers feed input to the compressor.
# This means a single zip that contains files from
# snappy's microbenchmark is well-suited for seeding
# both fuzzers. The files used for microbenchmarking
# are available in the directory named "testdata"
# relative to project root.
zip -rjq $OUT/snappy_compress_fuzzer_seed_corpus.zip ../testdata
cp $OUT/snappy_compress_fuzzer_seed_corpus.zip \
    $OUT/snappy_uncompress_fuzzer_seed_corpus.zip

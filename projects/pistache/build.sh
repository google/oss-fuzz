#!/bin/bash -eu
# Copyright 2021 Google LLC
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

mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=OFF -DPISTACHE_BUILD_TESTS=OFF ..
make pistache_static
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -o $OUT/fuzz_parsers \
    -std=c++17 -I../include/ ../tests/fuzzers/fuzz_parser.cpp ./src/libpistache.a

zip -q -r -j $OUT/fuzz_parsers_seed_corpus.zip ../tests/fuzzers/corpus

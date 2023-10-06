#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# copy corpuses
cp $SRC/libraw_cr2_fuzzer_seed_corpus.zip \
    $SRC/libraw_nef_fuzzer_seed_corpus.zip \
    $SRC/libraw_raf_fuzzer_seed_corpus.zip \
    $OUT/

# build project
autoreconf --install
./configure --disable-examples
make

# build fuzzers
$CXX $CXXFLAGS -std=c++11 -Ilibraw \
    $SRC/libraw_fuzzer.cc -o $OUT/libraw_fuzzer \
    $LIB_FUZZING_ENGINE -lz lib/.libs/libraw.a

$CXX $CXXFLAGS -std=c++11 -Ilibraw \
    $SRC/libraw_fuzzer.cc -o $OUT/libraw_cr2_fuzzer \
    $LIB_FUZZING_ENGINE -lz lib/.libs/libraw.a

$CXX $CXXFLAGS -std=c++11 -Ilibraw \
    $SRC/libraw_fuzzer.cc -o $OUT/libraw_nef_fuzzer \
    $LIB_FUZZING_ENGINE -lz lib/.libs/libraw.a

$CXX $CXXFLAGS -std=c++11 -Ilibraw \
    $SRC/libraw_fuzzer.cc -o $OUT/libraw_raf_fuzzer \
    $LIB_FUZZING_ENGINE -lz lib/.libs/libraw.a

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

mkdir build
cd build
cmake -DENABLE_LIB_ONLY=ON -DENABLE_STATIC_LIB=ON -DHAVE_CUNIT=ON ../
make
make check

$CXX $CXXFLAGS -std=c++11 -I../lib/includes -Ilib/includes -I../lib/ -I../tests/ \
    ../fuzz/fuzz_frames.cc -o $OUT/nghttp2_fuzzer_frames \
    tests/CMakeFiles/main.dir/nghttp2_test_helper.c.o \
    $LIB_FUZZING_ENGINE lib/libnghttp2.a

$CXX $CXXFLAGS -std=c++11 -I../lib/includes -Ilib/includes -I../lib/ \
    ../fuzz/fuzz_target.cc -o $OUT/nghttp2_fuzzer \
    $LIB_FUZZING_ENGINE lib/libnghttp2.a

$CXX $CXXFLAGS -std=c++11 -I../lib/includes -Ilib/includes -I../lib/ \
    ../fuzz/fuzz_target_fdp.cc -o $OUT/nghttp2_fuzzer_fdp \
    $LIB_FUZZING_ENGINE lib/libnghttp2.a

cp $SRC/*.options $OUT

zip -j $OUT/nghttp2_fuzzer_seed_corpus.zip ../fuzz/corpus/*/*

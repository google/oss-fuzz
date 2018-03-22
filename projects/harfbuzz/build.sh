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

# Disable:
# 1. UBSan vptr since target built with -fno-rtti.
# 2. UBSan function to avoid crashes with void* cast crashes.
export CFLAGS="$CFLAGS -fno-sanitize=function,vptr"
export CXXFLAGS="$CXXFLAGS -fno-sanitize=function,vptr"

# Build the library.
./autogen.sh
./configure
make clean
make -j$(nproc) V=1 all
make CPPFLAGS="-DHB_NO_VISIBILITY" -C src V=1 fuzzing

# Build the fuzzer.
$CXX $CXXFLAGS -std=c++11 -Isrc \
    ./test/fuzzing/hb-shape-fuzzer.cc -o $OUT/hb-shape-fuzzer \
    -lFuzzingEngine ./src/.libs/libharfbuzz-fuzzing.a

$CXX $CXXFLAGS -std=c++11 -Isrc \
    ./test/fuzzing/hb-subset-fuzzer.cc -o $OUT/hb-subset-fuzzer \
    -lFuzzingEngine ./src/.libs/libharfbuzz-subset-fuzzing.a ./src/.libs/libharfbuzz-fuzzing.a

# Archive and copy to $OUT seed corpus if the build succeeded.
zip -j -r $OUT/hb-shape-fuzzer_seed_corpus.zip $SRC/harfbuzz/test/shaping/data/in-house/fonts
zip -j -r $OUT/hb-subset-fuzzer_seed_corpus.zip $SRC/harfbuzz/test/api/fonts

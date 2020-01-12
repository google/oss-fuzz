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
export CFLAGS="$CFLAGS -fno-sanitize=vptr"
export CXXFLAGS="$CXXFLAGS -fno-sanitize=vptr"

# Build the library.
./autogen.sh
./configure --enable-static --disable-shared
make clean
make -j$(nproc) CPPFLAGS="-DHB_NO_VISIBILITY" V=1 all

# Build the fuzzer.
$CXX $CXXFLAGS -std=c++11 -Isrc \
    ./test/fuzzing/hb-shape-fuzzer.cc -o $OUT/hb-shape-fuzzer \
    $LIB_FUZZING_ENGINE ./src/.libs/libharfbuzz.a

$CXX $CXXFLAGS -std=c++11 -Isrc \
    ./test/fuzzing/hb-subset-fuzzer.cc -o $OUT/hb-subset-fuzzer \
    $LIB_FUZZING_ENGINE ./src/.libs/libharfbuzz-subset.a ./src/.libs/libharfbuzz.a

# Archive and copy to $OUT seed corpus if the build succeeded.
mkdir all-fonts
for d in \
	test/shaping/data/in-house/fonts \
	test/shaping/data/aots/fonts \
	test/shaping/data/text-rendering-tests/fonts \
	test/api/fonts \
	test/fuzzing/fonts \
	perf/fonts \
	; do
	cp $d/* all-fonts/
done
zip $OUT/hb-shape-fuzzer_seed_corpus.zip all-fonts/*
cp $OUT/hb-shape-fuzzer_seed_corpus.zip $OUT/hb-subset-fuzzer_seed_corpus.zip

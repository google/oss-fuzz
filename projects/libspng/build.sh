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

if [[ $CFLAGS = *-m32* ]]
then
    sed -i "s|/usr/bin/clang|$CC|g" tests/cross_oss_fuzz.txt
    sed -i "s|/usr/bin/clang++|$CXX|g" tests/cross_oss_fuzz.txt
    sed -i "s|cflags|$CFLAGS|g" tests/cross_oss_fuzz.txt
    sed -i "s|ldflags|-m32|g" tests/cross_oss_fuzz.txt
    meson --wrap-mode=forcefallback --default-library=static --buildtype=plain --cross-file=tests/cross_oss_fuzz.txt build
else
    meson --wrap-mode=forcefallback --default-library=static --buildtype=plain build
fi


cat $SRC/libspng/tests/cross_oss_fuzz.txt

ninja -C build

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/libspng/tests/spng_read_fuzzer.cc \
    -o $OUT/spng_read_fuzzer \
    $LIB_FUZZING_ENGINE $SRC/libspng/build/libspng.a $SRC/libspng/build/subprojects/zlib-1.2.11/libz.a

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/libspng/tests/spng_read_fuzzer.cc \
    -o $OUT/spng_read_fuzzer_structure_aware \
    -include ../fuzzer-test-suite/libpng-1.2.56/png_mutator.h \
    -D PNG_MUTATOR_DEFINE_LIBFUZZER_CUSTOM_MUTATOR \
    $LIB_FUZZING_ENGINE $SRC/libspng/build/libspng.a $SRC/libspng/build/subprojects/zlib-1.2.11/libz.a

find $SRC/libspng/tests/images -name "*.png" | \
     xargs zip $OUT/spng_read_fuzzer_seed_corpus.zip

cp $SRC/libspng/tests/spng.dict \
   $SRC/libspng/tests/spng_read_fuzzer.options $OUT/

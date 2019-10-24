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
# Run the OSS-Fuzz script in the project
#$SRC/libspng/tests/ossfuzz.sh

wget http://www.zlib.net/zlib-1.2.11.tar.gz
tar xzvf zlib-1.2.11.tar.gz
mkdir zlib-1.2.11/build
cd zlib-1.2.11/build
cmake ..
make -j$(nproc) install
cd ../..

mkdir build
cd build
cmake -DSPNG_STATIC=ON ..
make -j$(nproc)
cd ..

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/libspng/tests/spng_read_fuzzer.cc \
    -o $OUT/spng_read_fuzzer \
    $LIB_FUZZING_ENGINE $SRC/libspng/build/libspng_static.a $SRC/libspng/zlib-1.2.11/build/libz.a

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/libspng/tests/spng_read_fuzzer.cc \
    -o $OUT/spng_read_fuzzer_structure_aware \
    -include $SRC/fuzzer-test-suite/libpng-1.2.56/png_mutator.h \
    -D PNG_MUTATOR_DEFINE_LIBFUZZER_CUSTOM_MUTATOR \
    $LIB_FUZZING_ENGINE $SRC/libspng/build/libspng_static.a $SRC/libspng/zlib-1.2.11/build/libz.a

find $SRC/libspng/tests/images -name "*.png" | \
     xargs zip $OUT/spng_read_fuzzer_seed_corpus.zip

cp $SRC/libspng/tests/spng.dict \
   $SRC/libspng/tests/spng_read_fuzzer.options $OUT/

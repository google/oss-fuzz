#!/bin/bash -eu
# Copyright 2022 Google LLC
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
#Patch
cp patch/CMakeLists.patch .
cp -r patch/fuzzers .
patch < CMakeLists.patch

#Dir
mkdir build
cd build

#Build
cmake \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CFLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$CFLAGS" -DLIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" \
    -DCMAKE_BUILD_TYPE=Debug -DBUILD_STATIC=ON -DFUZZER=ON ../

make -j$(nproc)

#SetUp
cp fuzzers/mapfuzzer $OUT/mapfuzzer
cp fuzzers/shapefuzzer $OUT/shapefuzzer

cd ../
zip -r $OUT/mapfuzzer_seed_corpus.zip tests/*.map
zip -r $OUT/shapefuzzer_seed_corpus.zip tests/*.shp tests/*.shx tests/*.dbf

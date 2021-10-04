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

mv $SRC/ZydisFuzz_seed_corpus.zip $OUT/ZydisFuzz_seed_corpus.zip

mkdir build && cd build

cmake                                   \
    -DZYAN_FORCE_ASSERTS=ON             \
    -DZYDIS_BUILD_EXAMPLES=OFF          \
    -DZYDIS_BUILD_TOOLS=OFF             \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo   \
    -DCMAKE_C_COMPILER=$CC              \
    -DCMAKE_CXX_COMPILER=$CXX           \
    -DCMAKE_C_FLAGS="$CFLAGS"           \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS"       \
    ..

make -j$(nproc) VERBOSE=1

$CXX                                    \
    $CXXFLAGS                           \
    $LIB_FUZZING_ENGINE                 \
    ../tools/ZydisFuzzIn.c              \
    -DZYDIS_LIBFUZZER                   \
    -o $OUT/ZydisFuzz                   \
    -I .                                \
    -I ./zycore                         \
    -I ../include                       \
    -I ../dependencies/zycore/include   \
    ./libZydis.a


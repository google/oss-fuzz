#!/bin/bash -eux
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

# build project with cmake
export ASAN_OPTIONS=detect_leaks=0
mkdir -p build
cd build
cmake .. -DCMAKE_C_COMPILER="$CC" \
         -DCMAKE_CXX_COMPILER="$CXX" \
         -DCMAKE_C_FLAGS="$CFLAGS" \
         -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
         -DBUILD_SHARED_LIBS=OFF
make -j$(nproc)
cd ..

# Build the ssml-fuzzer manually with $LIB_FUZZING_ENGINE
$CC $CFLAGS -Ibuild/src/libespeak-ng/include -I. -Isrc/include -c tests/ssml-fuzzer.c -o tests/ssml-fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE tests/ssml-fuzzer.o \
    build/src/libespeak-ng/libespeak-ng.a \
    build/src/speechPlayer/libspeechPlayer.a \
    build/src/ucd-tools/libucd.a -o $OUT/ssml-fuzzer -lm

cp -r build/espeak-ng-data/ $OUT/

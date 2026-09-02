#!/bin/bash -eu
# Copyright 2026 Google LLC
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

mkdir build && cd build
cmake -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
      -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      -DDRACO_TESTS=OFF -DDRACO_JS_GLUE=OFF ..
make -j$(nproc) draco_static

cd $SRC
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_decode.cc \
    -I/src/draco/src -I/src/draco/build \
    /src/draco/build/libdraco.a \
    -o $OUT/fuzz_decode

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

cmake . -DBUILD_TESTING=OFF
make clean
make -j$(nproc) brunslidec-static

# TODO(eustas): add seed corpus

$CXX $CXXFLAGS -std=c++11 -I./c/include c/tests/fuzz_decode.cc \
    -o $OUT/fuzz_decode $LIB_FUZZING_ENGINE \
    ./artifacts/libbrunslidec-static.a ./artifacts/libbrunslicommon-static.a \
    ./_deps/brotli-build/libbrotlidec-static.a \
    ./_deps/brotli-build/libbrotlicommon-static.a

$CXX $CXXFLAGS -std=c++11 -I./c/include c/tests/fuzz_decode_streaming.cc \
    -o $OUT/fuzz_decode_streaming $LIB_FUZZING_ENGINE \
    ./artifacts/libbrunslidec-static.a ./artifacts/libbrunslicommon-static.a \
    ./_deps/brotli-build/libbrotlidec-static.a \
    ./_deps/brotli-build/libbrotlicommon-static.a

#!/bin/bash -eu
# Copyright 2026 Google LLC.
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

# Offline rebuild of the project and its fuzzers.

# Ensure gtest bump is applied.
sed -i 's/e2239ee6043f73722e7aa812a459f54a28552929/6910c9d9165801d8827d628cb72eb7ea9dd538c5/g' CMakeLists.txt

# Re-run cmake to ensure build system is up to date, but fully disconnected.
cmake . -DBUILD_TESTING=ON -DFETCHCONTENT_FULLY_DISCONNECTED=ON
make -j$(nproc) all

# Re-compile fuzzers.
$CXX $CXXFLAGS -std=c++11 -I./c/include c/tests/fuzz_decode.cc \
    ./CMakeFiles/build_huffman_table_test.dir/c/tests/test_utils.cc.o \
    -o $OUT/fuzz_decode $LIB_FUZZING_ENGINE \
    ./artifacts/libbrunslidec-static.a ./artifacts/libbrunslicommon-static.a \
    ./_deps/brotli-build/libbrotlidec-static.a \
    ./_deps/brotli-build/libbrotlicommon-static.a

$CXX $CXXFLAGS -std=c++11 -I./c/include c/tests/fuzz_decode_streaming.cc \
    ./CMakeFiles/build_huffman_table_test.dir/c/tests/test_utils.cc.o \
    -o $OUT/fuzz_decode_streaming $LIB_FUZZING_ENGINE \
    ./artifacts/libbrunslidec-static.a ./artifacts/libbrunslicommon-static.a \
    ./_deps/brotli-build/libbrotlidec-static.a \
    ./_deps/brotli-build/libbrotlicommon-static.a

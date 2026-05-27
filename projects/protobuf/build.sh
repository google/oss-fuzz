#!/bin/bash -eu
# Copyright 2024 Google LLC
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

set -o nounset
set -o errexit
set -o pipefail

cd $SRC/protobuf

# Update submodules (third-party deps)
git submodule update --init --recursive

# Configure with CMake
mkdir -p build && cd build
cmake .. \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="${CC}" \
    -DCMAKE_CXX_COMPILER="${CXX}" \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    -DCMAKE_EXE_LINKER_FLAGS="${LIB_FUZZING_ENGINE}" \
    -Dprotobuf_BUILD_TESTS=OFF \
    -Dprotobuf_BUILD_FUZZ_TESTS=ON \
    -Dprotobuf_BUILD_SHARED_LIBS=OFF \
    -Dprotobuf_ABSL_PROVIDER=package \
    -DABSL_PROPAGATE_CXX_STD=ON

ninja -j$(nproc) protobuf

# Path to built static libraries
LIBDIR="$SRC/protobuf/build"

# Include dirs
INCLUDES="-I$SRC/protobuf/src"

# Compile proto_decode_fuzzer
$CXX $CXXFLAGS $INCLUDES \
    $SRC/proto_decode_fuzzer.cc \
    -o $OUT/proto_decode_fuzzer \
    $LIB_FUZZING_ENGINE \
    "$LIBDIR/libprotobuf.a" \
    "$LIBDIR/libprotobuf-lite.a" 2>/dev/null || \
$CXX $CXXFLAGS $INCLUDES \
    $SRC/proto_decode_fuzzer.cc \
    -o $OUT/proto_decode_fuzzer \
    $LIB_FUZZING_ENGINE \
    $(find "$LIBDIR" -name "libprotobuf*.a" | tr '\n' ' ')

# Compile proto_json_fuzzer
$CXX $CXXFLAGS $INCLUDES \
    $SRC/proto_json_fuzzer.cc \
    -o $OUT/proto_json_fuzzer \
    $LIB_FUZZING_ENGINE \
    "$LIBDIR/libprotobuf.a" \
    "$LIBDIR/libprotobuf-lite.a" 2>/dev/null || \
$CXX $CXXFLAGS $INCLUDES \
    $SRC/proto_json_fuzzer.cc \
    -o $OUT/proto_json_fuzzer \
    $LIB_FUZZING_ENGINE \
    $(find "$LIBDIR" -name "libprotobuf*.a" | tr '\n' ' ')

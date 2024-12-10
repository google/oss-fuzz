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

# Update submodule
./checkout_glslang_spirv_tools.sh
NPROC="--parallel $(nproc)" ./build_glslang_spirv_tools.sh

# Build spirv-cross binaries with debug options
cmake -S . -B build/ -D CMAKE_BUILD_TYPE=Debug \
    -D CMAKE_CXX_FLAGS="$CXXFLAGS -pthread -stdlib=libc++"
cmake --build build --config Debug --parallel $(nproc)

# Copy built binaries of the spirv-cross project
for fuzzers in $(find $SRC -maxdepth 1 -name '*_fuzzer.cpp'); do
    fuzz_basename=$(basename -s .cpp $fuzzers)
    $CXX $CXXFLAGS -std=c++17 -I$SRC/spirv-cross \
        -I$SRC/spirv-cross/external/spirv-tools \
        -I$SRC/spirv-cross/external/spirv-tools/include \
        -c $fuzzers -o $fuzz_basename.o

    $CXX $CXXFLAGS -std=c++17 $LIB_FUZZING_ENGINE \
        $fuzz_basename.o -o $OUT/$fuzz_basename \
        -Wl,--start-group \
        $SRC/spirv-cross/build/*.a \
        $SRC/spirv-cross/external/glslang-build/output/lib/*.a \
        -Wl,--end-group
done

cd $SRC/
mkdir -p spirv-corpus
find $SRC/spirv-cross -name "*.spv" -exec cp {} $SRC/spirv-corpus \;
zip -q -r -j $OUT/parser_fuzzer_seed_corpus.zip $SRC/spirv-corpus/*

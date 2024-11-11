#!/bin/bash -eu
#
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

# Sync dependencies
./utils/git-sync-deps

# Build the project binaries with ninja and cmake
mkdir -p build
pushd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="$CXXFLAGS -pthread -stdlib=libc++" ..
ninja -v
popd

$CXX $CXXFLAGS -I$SRC/shaderc/libshaderc/include \
    -I$SRC/shaderc/libshaderc_util/include \
    -I$SRC/shaderc/glslc/src -I$SRC/shaderc/third_party/glslang \
    -c $SRC/glslc_fuzzer.cc -o glslc_fuzzer.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    glslc_fuzzer.o -o $OUT/glslc_fuzzer \
    -Wl,--start-group \
    $SRC/shaderc/build/libshaderc/*.a \
    $SRC/shaderc/build/libshaderc_util/libshaderc_util.a \
    $SRC/shaderc/build/glslc/libglslc.a \
    -Wl,--end-group

zip -q $OUT/glslc_fuzzer_seed_corpus.zip $SRC/glsl_seed/*

#!/bin/bash -eu
#
# Copyright 2021 Google Inc.
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

set -eu

#
# Build Zydis library.
#

mkdir build && cd build

cmake                                       \
    -DZYAN_FORCE_ASSERTS=ON                 \
    -DZYDIS_BUILD_EXAMPLES=OFF              \
    -DZYDIS_BUILD_TOOLS=OFF                 \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo       \
    "-DCMAKE_C_COMPILER=${CC}"              \
    "-DCMAKE_CXX_COMPILER=${CXX}"           \
    "-DCMAKE_C_FLAGS=${CFLAGS}"             \
    "-DCMAKE_CXX_FLAGS=${CXXFLAGS}"         \
    ..

make -j$(nproc) VERBOSE=1

#
# Build fuzzing tools.
#

function build_fuzzer() {
    source_file="${1}"
    max_len="${2}"
    executable="${source_file%.c}"

    $CC                                     \
        $CFLAGS                             \
        -c                                  \
        "../tools/${source_file}"           \
        ../tools/ZydisFuzzShared.c          \
        -DZYDIS_LIBFUZZER                   \
        -I .                                \
        -I ./zycore                         \
        -I ../include                       \
        -I ../dependencies/zycore/include

     $CXX                                   \
        $CXXFLAGS                           \
        "${LIB_FUZZING_ENGINE}"             \
        "$executable.o"                      \
        ZydisFuzzShared.o                   \
        -DZYDIS_LIBFUZZER                   \
        -o "${OUT}/${executable}"           \
        ./libZydis.a

    echo -e "[libfuzzer]\nmax_len = ${max_len}" > "${OUT}/${executable}.options"
}

build_fuzzer "ZydisFuzzDecoder.c"    350
build_fuzzer "ZydisFuzzEncoder.c"    450
build_fuzzer "ZydisFuzzReEncoding.c" 100

#
# Place fuzzing corpora where they belong.
#

cp ${SRC}/Zydis*_seed_corpus.zip ${OUT}

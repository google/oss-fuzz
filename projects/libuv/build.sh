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

# Build libuv with fuzzing instrumentation.
#
# Targets:
#   fuzz_idna       — uv__idna_toascii() IDNA/Punycode Unicode hostname encoder
#   fuzz_url_parse  — uv_url_t URL parser (used by Node.js URL API)

cd $SRC/libuv

# Build libuv as a static library
mkdir -p build && cd build

cmake .. \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DBUILD_SHARED_LIBS=OFF \
    -DLIBUV_BUILD_TESTS=OFF \
    -DLIBUV_BUILD_BENCH=OFF \
    2>&1 | tail -10

make -j$(nproc) uv_a 2>&1 | tail -10

cd $SRC/libuv

# Build fuzz_idna
$CC $CFLAGS \
    -I$SRC/libuv/include \
    -I$SRC/libuv/src \
    $SRC/oss-fuzz/projects/libuv/fuzz_idna.c \
    $SRC/libuv/build/libuv_a.a \
    $LIB_FUZZING_ENGINE \
    -o $OUT/fuzz_idna

# Build fuzz_url_parse (only if libuv was built with URL support)
$CC $CFLAGS \
    -I$SRC/libuv/include \
    -I$SRC/libuv/src \
    $SRC/oss-fuzz/projects/libuv/fuzz_url_parse.c \
    $SRC/libuv/build/libuv_a.a \
    $LIB_FUZZING_ENGINE \
    -o $OUT/fuzz_url_parse || true

# Seed corpus: valid IDN hostnames as starting points
zip -j $OUT/fuzz_idna_seed_corpus.zip \
    $SRC/oss-fuzz/projects/libuv/corpus/idna/*.txt 2>/dev/null || true

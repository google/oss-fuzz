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
#
################################################################################

# Build libnfs as a static library with the fuzzing compilers and flags.
cd $SRC/libnfs
rm -rf build
cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_TESTS=OFF \
    -DENABLE_UTILS=OFF \
    -DENABLE_EXAMPLES=OFF \
    -DENABLE_DOCUMENTATION=OFF
cmake --build build -j$(nproc)

# Compile the fuzz target as C and link with the CXX driver, since the
# fuzzing engine archive pulls in C++ symbols on some engines.
$CC $CFLAGS -std=c11 \
    -I $SRC/libnfs/include \
    -I $SRC/libnfs/include/nfsc \
    -I $SRC/libnfs/nfs \
    -I $SRC/libnfs/mount \
    -I $SRC/libnfs/nlm \
    -I $SRC/libnfs/rquota \
    -I $SRC/libnfs/portmap \
    -I $SRC/libnfs/nfs4 \
    -I $SRC/libnfs/build \
    -c $SRC/libnfs/fuzzing/libnfs_reply_fuzzer.c \
    -o $WORK/libnfs_reply_fuzzer.o
$CXX $CXXFLAGS \
    $WORK/libnfs_reply_fuzzer.o \
    $SRC/libnfs/build/lib/libnfs.a \
    $LIB_FUZZING_ENGINE -lpthread \
    -o $OUT/libnfs_reply_fuzzer

# Seed corpus spanning the decoder table.
zip -j -q $OUT/libnfs_reply_fuzzer_seed_corpus.zip $SRC/libnfs/fuzzing/seeds/*

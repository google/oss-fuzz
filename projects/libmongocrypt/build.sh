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

cd $SRC/libmongocrypt

# Build the library
mkdir -p build
cd build

# Configure with CMake
# Note: OSS-Fuzz sets CC, CXX, CFLAGS, CXXFLAGS, LIB_FUZZING_ENGINE
# ENABLE_FUZZING defines the fuzz_mongocrypt and fuzz_kms targets
cmake .. \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    -DENABLE_ONLINE_TESTS=OFF \
    -DENABLE_STATIC=ON \
    -DENABLE_FUZZING=ON

# Build the fuzzing targets using the CMake fuzzing targets.
make -j$(nproc) fuzz_mongocrypt fuzz_kms
cp fuzz_mongocrypt $OUT/fuzz_mongocrypt
cp fuzz_kms $OUT/fuzz_kms

# Package seed corpus for fuzz_mongocrypt
mkdir -p $OUT/fuzz_mongocrypt_seed_corpus
cp ../test/data/fuzz_mongocrypt_corpus/* $OUT/fuzz_mongocrypt_seed_corpus/
zip -j $OUT/fuzz_mongocrypt_seed_corpus.zip $OUT/fuzz_mongocrypt_seed_corpus/*


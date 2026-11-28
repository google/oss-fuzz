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

cd $SRC/faiss

mkdir -p build
cd build
cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DFAISS_ENABLE_GPU=OFF \
    -DFAISS_ENABLE_PYTHON=OFF \
    -DFAISS_ENABLE_C_API=OFF \
    -DBUILD_TESTING=OFF \
    -DFAISS_OPT_LEVEL=generic \
    -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_C_COMPILER=$CC \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    ..
make -j$(nproc) faiss

cd $SRC

$CXX $CXXFLAGS -std=c++17 \
    -I$SRC/faiss \
    -I$SRC/faiss/build/faiss \
    $SRC/faiss_fuzz_harness.cpp \
    $SRC/faiss/build/faiss/libfaiss.a \
    $LIB_FUZZING_ENGINE \
    -fopenmp -lopenblas -lgfortran -lpthread \
    -o $OUT/faiss_fuzz

cp $SRC/faiss_fuzz_seed_corpus.zip $OUT/faiss_fuzz_seed_corpus.zip
cp $SRC/faiss_fuzz.dict $OUT/faiss_fuzz.dict

#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

cd $WORK
cmake -G Ninja -DBUILD_TESTING=false $SRC/bloaty
ninja -j$(nproc)
cp fuzz_target $OUT
zip -j $OUT/fuzz_target_seed_corpus.zip $SRC/bloaty/tests/testdata/fuzz_corpus/*

# Build the project tests for Chronos
cd $WORK
unset LIB_FUZZING_ENGINE
cmake -G Ninja \
  -DBUILD_TESTING=true \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_FLAGS="" \
  -DCMAKE_CXX_FLAGS="-stdlib=libc++" \
  -DCMAKE_EXE_LINKER_FLAGS="-stdlib=libc++" \
  -DCMAKE_SHARED_LINKER_FLAGS="" \
  $SRC/bloaty -B build-tests
ninja -C build-tests -j$(nproc)

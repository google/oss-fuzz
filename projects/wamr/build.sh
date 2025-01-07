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

echo "<| ------ " $(pwd) " ------ |>"
ls .
ls -l /usr/lib/libFuzzing*
echo "<| ------  --------  ------ |>"


: ${LD:="${CXX}"}
: ${LDFLAGS:="${CXXFLAGS}"}  # to make sure we link with sanitizer runtime

cmake_args=(
  # C compiler
  -DCMAKE_C_COMPILER="${CC}"
  -DCMAKE_C_FLAGS="${CFLAGS}"

  # C++ compiler
  -DCMAKE_CXX_COMPILER="${CXX}"
  -DCMAKE_CXX_FLAGS="${CXXFLAGS}"

  # Linker
  -DCMAKE_LINKER="${LD}"
  -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}"
  -DCMAKE_MODULE_LINKER_FLAGS="${LDFLAGS}"
  -DCMAKE_SHARED_LINKER_FLAGS="${LDFLAGS}"
)

# CORPUS
(
  cd tests/fuzz/wasm-mutator-fuzz/
  ./smith_wasm.sh 10
)

# loader
(
  cd tests/fuzz/wasm-mutator-fuzz/

  cmake -S . -B build_loader \
      "${cmake_args[@]}" \
    && cmake --build build_loader

  cp ./build_loader/wasm_mutator_fuzz $OUT/wasm_mutator_fuzz_loader
  zip -j $OUT/wasm_mutator_fuzz_loader_seed_corpus.zip ./build/CORPUS_DIR/test_*.wasm
)

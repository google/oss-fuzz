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

# avoid `-stdlib=libc++` by not using ${CXX} and ${CXXFLAGS}
# to make sure we link with sanitizer runtime
: ${LD:="${CC}"}
: ${LDFLAGS:="${CFLAGS}"}

cmake_args=(
  # C compiler
  -DCMAKE_C_COMPILER="${CC}"
  -DCMAKE_C_FLAGS="${CFLAGS}"

  # C++ compiler
  # avoid `-stdlib=libc++` by not using ${CXX} and ${CXXFLAGS}
  -DCMAKE_CXX_COMPILER="${CC}"
  -DCMAKE_CXX_FLAGS="${CFLAGS}"

  # Linker
  -DCMAKE_LINKER="${LD}"
  -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}"
  -DCMAKE_MODULE_LINKER_FLAGS="${LDFLAGS}"
  -DCMAKE_SHARED_LINKER_FLAGS="${LDFLAGS}"
)

# CORPUS
(
  echo "Building seed corpus...\n"
  cd tests/fuzz/wasm-mutator-fuzz/
  ./smith_wasm.sh 10

  zip -j ./build/seed_corpus.zip ./build/CORPUS_DIR/test_*.wasm
)

# fuzzing target

# classic-interp
(
  echo "Building classic interp...\n"
  cd tests/fuzz/wasm-mutator-fuzz/

  cmake -S . -B build-classic-interp \
      -DCMAKE_TOOLCHAIN_FILE=./clang_toolchain.cmake \
      -DLLVM_DIR=/opt/llvm-15.0.6/lib/cmake/llvm \
      -G Ninja \
      -DWAMR_BUILD_FAST_INTERP=0 \
      "${cmake_args[@]}" \
    && cmake --build build-classic-interp

  cp ./build-classic-interp/wasm-mutator/wasm_mutator_fuzz $OUT/wamr_fuzz_classic_interp
  cp ./build/seed_corpus.zip $OUT/wamr_fuzz_classic_interp_seed_corpus.zip
)

## fast-interp (by default)
(
  echo "Building fast interp...\n"
  cd tests/fuzz/wasm-mutator-fuzz/

  cmake -S . -B build-fast-interp \
      -DCMAKE_TOOLCHAIN_FILE=./clang_toolchain.cmake \
      -DLLVM_DIR=/opt/llvm-15.0.6/lib/cmake/llvm \
      -G Ninja \
      "${cmake_args[@]}" \
    && cmake --build build-fast-interp

  cp ./build-fast-interp/wasm-mutator/wasm_mutator_fuzz $OUT/wamr_fuzz_fast_interp
  cp ./build/seed_corpus.zip $OUT/wamr_fuzz_fast_interp_seed_corpus.zip
)

## llvm-jit
(
  echo "Building llvm jit...\n"
  cd tests/fuzz/wasm-mutator-fuzz/

  cmake -S . -B build-llvm-jit \
      -DCMAKE_TOOLCHAIN_FILE=./clang_toolchain.cmake \
      -DLLVM_DIR=/opt/llvm-15.0.6/lib/cmake/llvm \
      -G Ninja \
      -DWAMR_BUILD_FAST_INTERP=0 \
      -DWAMR_BUILD_JIT=1 \
      "${cmake_args[@]}" \
    && cmake --build build-llvm-jit --target wasm_mutator_fuzz

  cp ./build-llvm-jit/wasm-mutator/wasm_mutator_fuzz $OUT/wamr_fuzz_llvm_jit
  cp ./build/seed_corpus.zip $OUT/wamr_fuzz_llvm_jit_seed_corpus.zip
)

# aot-compiler
(
  echo "Building aot compiler...\n"
  cd tests/fuzz/wasm-mutator-fuzz/

  cmake -S . -B build-aot-compiler \
      -DCMAKE_TOOLCHAIN_FILE=./clang_toolchain.cmake \
      -DLLVM_DIR=/opt/llvm-15.0.6/lib/cmake/llvm \
      -G Ninja \
      "${cmake_args[@]}" \
    && cmake --build build-aot-compiler --target aot_compiler_fuzz

  cp ./build-aot-compiler/aot-compiler/aot_compiler_fuzz $OUT/wamr_fuzz_aot_compiler
  cp ./build/seed_corpus.zip $OUT/wamr_fuzz_aot_compiler_seed_corpus.zip
)

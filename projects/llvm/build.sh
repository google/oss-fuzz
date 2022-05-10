#!/bin/bash -eux
#
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

# Dont check Coverage in CI as it gets killed
if [[ -n "${OSS_FUZZ_CI-}" && "$SANITIZER" = coverage ]]; then
  touch $OUT/exit
  exit 0
fi

if [ -n "${OSS_FUZZ_CI-}" ]; then
  readonly FUZZERS=(\
    clang-fuzzer\
    llvm-itanium-demangle-fuzzer\
  )
else
  readonly FUZZERS=( \
    clang-fuzzer \
    clang-format-fuzzer \
    clang-objc-fuzzer \
    clangd-fuzzer \
    clang-pseudo-fuzzer \
    llvm-itanium-demangle-fuzzer \
    llvm-microsoft-demangle-fuzzer \
    llvm-dwarfdump-fuzzer \
    llvm-special-case-list-fuzzer \
  )
fi

case $SANITIZER in
  address) LLVM_SANITIZER="Address" ;;
  undefined) LLVM_SANITIZER="Undefined" ;;
  memory) LLVM_SANITIZER="MemoryWithOrigins" ;;
  *) LLVM_SANITIZER="" ;;
esac
case "${LIB_FUZZING_ENGINE}" in
  -fsanitize=fuzzer) CMAKE_FUZZING_CONFIG="-DLLVM_USE_SANITIZE_COVERAGE=ON" ;;
  *) CMAKE_FUZZING_CONFIG="-DLLVM_LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE}" ;;
esac

LLVM=llvm-project/llvm

mkdir build
cd build

cmake -GNinja -DCMAKE_BUILD_TYPE=Release ../$LLVM \
    -DLLVM_ENABLE_PROJECTS="clang;libcxx;libcxxabi;compiler-rt;lld;clang-tools-extra" \
    -DLLVM_ENABLE_ASSERTIONS=ON \
    -DCMAKE_C_COMPILER="${CC}" \
    -DCMAKE_CXX_COMPILER="${CXX}" \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    "${CMAKE_FUZZING_CONFIG}" \
    -DLLVM_NO_DEAD_STRIP=ON \
    -DLLVM_USE_SANITIZER="${LLVM_SANITIZER}" \
    -DLLVM_EXPERIMENTAL_TARGETS_TO_BUILD=WebAssembly \
    -DCOMPILER_RT_INCLUDE_TESTS=OFF

for fuzzer in "${FUZZERS[@]}"; do
  ninja $fuzzer
  cp bin/$fuzzer $OUT
done

zip -j "${OUT}/clang-objc-fuzzer_seed_corpus.zip"  $SRC/$LLVM/../clang/tools/clang-fuzzer/corpus_examples/objc/*
zip -j "${OUT}/clangd-fuzzer_seed_corpus.zip"  $SRC/$LLVM/../clang-tools-extra/clangd/test/*

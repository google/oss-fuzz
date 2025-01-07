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

if [ -n "${OSS_FUZZ_CI-}" ]; then
  readonly FUZZERS=(\
    llvm-dwarfdump-fuzzer \
  )
else
  # For coverage we skip "clangd-fuzzer" because it eats too much memory
  # and the process gets killed.
  if [[ "$SANITIZER" = coverage ]]; then
    readonly FUZZERS=( \
      llvm-microsoft-demangle-fuzzer \
      llvm-dwarfdump-fuzzer \
      llvm-itanium-demangle-fuzzer \
      llvm-yaml-numeric-parser-fuzzer \
      llvm-yaml-parser-fuzzer \
      llvm-dlang-demangle-fuzzer \
      vfabi-demangler-fuzzer \
      llvm-rust-demangle-fuzzer \
      llvm-dis-fuzzer \
      llvm-opt-fuzzer \
      llvm-isel-fuzzer \
      llvm-special-case-list-fuzzer \
      clang-objc-fuzzer \
      clang-format-fuzzer \
      clang-fuzzer \
      llvm-parse-assembly-fuzzer \
      llvm-symbol-reader-fuzzer \
      llvm-object-yaml-fuzzer \
    )
  else
    readonly FUZZERS=( \
      llvm-microsoft-demangle-fuzzer \
      llvm-dwarfdump-fuzzer \
      llvm-itanium-demangle-fuzzer \
      llvm-yaml-numeric-parser-fuzzer \
      llvm-yaml-parser-fuzzer \
      llvm-dlang-demangle-fuzzer \
      vfabi-demangler-fuzzer \
      llvm-rust-demangle-fuzzer \
      llvm-dis-fuzzer \
      llvm-opt-fuzzer \
      llvm-isel-fuzzer \
      llvm-special-case-list-fuzzer \
      clang-objc-fuzzer \
      clang-format-fuzzer \
      clang-fuzzer \
      clangd-fuzzer \
      llvm-parse-assembly-fuzzer \
      llvm-symbol-reader-fuzzer \
      llvm-object-yaml-fuzzer \
    )
  fi
fi
# Fuzzers whose inputs are C-family source can use clang-fuzzer-dictionary.
readonly CLANG_DICT_FUZZERS=( \
  clang-fuzzer \
  clang-format-fuzzer \
  clang-objc-fuzzer \
)

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
    -DLLVM_ENABLE_PROJECTS="clang;lld;clang-tools-extra" \
    -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;compiler-rt" \
    -DLLVM_ENABLE_ASSERTIONS=ON \
    -DLLVM_USE_LINKER=lld \
    -DCMAKE_C_COMPILER="${CC}" \
    -DCMAKE_CXX_COMPILER="${CXX}" \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    "${CMAKE_FUZZING_CONFIG}" \
    -DLLVM_NO_DEAD_STRIP=ON \
    -DLLVM_USE_SANITIZER="${LLVM_SANITIZER}" \
    -DLLVM_EXPERIMENTAL_TARGETS_TO_BUILD=WebAssembly \
    -DCOMPILER_RT_INCLUDE_TESTS=OFF

# Patch certain build rules in code coverage mode, as otherwise the process is killed.
# Verify we can build some of the troublesome rules by building them.
if [[ "$SANITIZER" = coverage ]]; then
  mv build.ninja ../
  python3 $SRC/coverage_patcher.py ../build.ninja build.ninja
  ninja lib/Target/AMDGPU/Utils/CMakeFiles/LLVMAMDGPUUtils.dir/AMDGPUBaseInfo.cpp.o -j $(( $(nproc) / 2))
  ninja lib/Target/AMDGPU/MCTargetDesc/CMakeFiles/LLVMAMDGPUDesc.dir/AMDGPUMCCodeEmitter.cpp.o -j $(( $(nproc) / 2))
fi

for fuzzer in "${FUZZERS[@]}"; do
  # Limit workload in CI
  if [ -n "${OSS_FUZZ_CI-}" ]; then
    ninja $fuzzer -j 3
  else
    # Do not exhaust memory limitations on the cloud machine, coverage
    # takes more resources which causes processes to crash.
    if [[ "$SANITIZER" = coverage ]]; then
      ninja $fuzzer -j $(( $(nproc) / 4)) || ninja $fuzzer -j 2 || ninja $fuzzer -j 1
    else
      ninja $fuzzer -j $(( $(nproc) / 4))
    fi
  fi
  cp bin/$fuzzer $OUT
done


# Exit early in the CI as the llvm-isel-fuzzer and opt fuzzer won't be there.
if [ -n "${OSS_FUZZ_CI-}" ]; then
  exit 0
fi

cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--hexagon-O2
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--riscv64-O2
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--mips64-O2
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--arm-O2
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--ppc64-O2
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--aarch64-O2
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--x86_64-O2
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--wasm32-O2
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--nvptx-O2
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--ve-O2
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--bpf-O2
mv $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--aarch64-gisel

# Same for llvm-opt-fuzzer
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-earlycse
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-simplifycfg
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-gvn
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-sccp

cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-loop_predication
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-guard_widening
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-loop_vectorize

cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-loop_unswitch
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-licm
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-indvars
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-strength_reduce

cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-irce

cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-dse
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-loop_idiom
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-reassociate
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-lower_matrix_intrinsics
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-memcpyopt
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-sroa

mv $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-instcombine


ninja clang-fuzzer-dictionary
for fuzzer in "${CLANG_DICT_FUZZERS[@]}"; do
  bin/clang-fuzzer-dictionary > $OUT/$fuzzer.dict
done

zip -j "${OUT}/clang-objc-fuzzer_seed_corpus.zip"  $SRC/$LLVM/../clang/tools/clang-fuzzer/corpus_examples/objc/*
zip -j "${OUT}/clangd-fuzzer_seed_corpus.zip"  $SRC/$LLVM/../clang-tools-extra/clangd/test/*
zip -j "${OUT}/clang-fuzzer_seed_corpus.zip" $SRC/llvm-project/clang/test/Parser/*.cpp

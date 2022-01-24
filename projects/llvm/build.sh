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
ninja llvm-as

# In CI we only check a single architecture to avoid CI exhaustion
if [ -n "${OSS_FUZZ_CI-}" ]; then
  exit 0
fi

# isel-fuzzer encodes its default flags in the name.
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--aarch64-O2
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--x86_64-O2
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--wasm32-O2
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

mv $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-instcombine

# Build corpus for the llvm-opt-fuzzer
function build_corpus {
  local lit_path="${1}"
  local fuzzer_name="${2}"

  [[ -e "${WORK}/corpus-tmp" ]] && rm -r "${WORK}/corpus-tmp"
  mkdir "${WORK}/corpus-tmp"

  cd "${SRC}"

  # Compile all lit tests into bitcode. Ignore possible llvm-as failures.
  find "${lit_path}" -name "*.ll" -print0 |
      xargs -t -i -0 -n1 sh -c "build/bin/llvm-as "{}" || true"

  # Move freshly created bitcode into temp directory.
  find "${lit_path}" -name "*.bc" -print0 |
      xargs -t -i -0 -n1 mv "{}" "${WORK}/corpus-tmp"

  # Archive the corpus.
  zip -j "${OUT}/${fuzzer_name}_seed_corpus.zip"  "${WORK}"/corpus-tmp/*

  rm -r "${WORK}/corpus-tmp"

  echo -e "[libfuzzer]\nmax_len = 0" > "${OUT}"/"${fuzzer_name}".options
}

build_corpus "$LLVM/test/Transforms/InstCombine/" "llvm-opt-fuzzer--x86_64-instcombine"
build_corpus "$LLVM/test/Transforms/EarlyCSE/" "llvm-opt-fuzzer--x86_64-earlycse"
build_corpus "$LLVM/test/Transforms/SimplifyCFG/" "llvm-opt-fuzzer--x86_64-simplifycfg"
build_corpus "$LLVM/test/Transforms/GVN/" "llvm-opt-fuzzer--x86_64-gvn"
build_corpus "$LLVM/test/Transforms/SCCP/" "llvm-opt-fuzzer--x86_64-sccp"

build_corpus "$LLVM/test/Transforms/LoopPredication/" "llvm-opt-fuzzer--x86_64-loop_predication"
build_corpus "$LLVM/test/Transforms/GuardWidening/" "llvm-opt-fuzzer--x86_64-guard_widening"
build_corpus "$LLVM/test/Transforms/LoopVectorize/" "llvm-opt-fuzzer--x86_64-loop_vectorize"

build_corpus "$LLVM/test/Transforms/LoopUnswitch/" "llvm-opt-fuzzer--x86_64-llvm-opt-fuzzer--x86_64-loop_unswitch"
build_corpus "$LLVM/test/Transforms/LICM/" "llvm-opt-fuzzer--x86_64-llvm-opt-fuzzer--x86_64-licm"
build_corpus "$LLVM/test/Transforms/IndVarSimplify/" "llvm-opt-fuzzer--x86_64-llvm-opt-fuzzer--x86_64-indvars"
build_corpus "$LLVM/test/Transforms/LoopStrengthReduce/" "llvm-opt-fuzzer--x86_64-llvm-opt-fuzzer--x86_64-strength_reduce"

build_corpus "$LLVM/test/Transforms/IRCE/" "llvm-opt-fuzzer--x86_64-llvm-opt-fuzzer--x86_64-irce"

zip -j "${OUT}/clang-objc-fuzzer_seed_corpus.zip"  $SRC/$LLVM/../clang/tools/clang-fuzzer/corpus_examples/objc/*
zip -j "${OUT}/clangd-fuzzer_seed_corpus.zip"  $SRC/$LLVM/../clang-tools-extra/clangd/test/*

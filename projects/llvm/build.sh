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

build_protobuf() {
  ./autogen.sh
  ./configure --disable-shared
  make -j $(nproc)
  make check -j $(nproc)
  make install
  ldconfig
}

(cd protobuf-3.3.0 && build_protobuf)

readonly FUZZERS=( \
  clang-fuzzer \
  clang-proto-fuzzer \
  clang-format-fuzzer \
  clangd-fuzzer \
  llvm-demangle-fuzzer \
  llvm-dwarfdump-fuzzer \
  llvm-isel-fuzzer \
  llvm-special-case-list-fuzzer \
  llvm-opt-fuzzer \
)
case $SANITIZER in
  address) LLVM_SANITIZER="Address" ;;
  undefined) LLVM_SANITIZER="Undefined" ;;
  memory) LLVM_SANITIZER="MemoryWithOrigins" ;;
  *) LLVM_SANITIZER="" ;;
esac

mkdir build
cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release ../llvm \
    -DLLVM_ENABLE_ASSERTIONS=ON \
    -DCMAKE_C_COMPILER="${CC}" \
    -DCMAKE_CXX_COMPILER="${CXX}" \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    -DLLVM_LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE}" \
    -DLLVM_NO_DEAD_STRIP=ON \
    -DCLANG_ENABLE_PROTO_FUZZER=ON \
    -DLLVM_USE_SANITIZER="${LLVM_SANITIZER}"
for fuzzer in "${FUZZERS[@]}"; do
  ninja $fuzzer
  cp bin/$fuzzer $OUT
done
ninja llvm-as

# isel-fuzzer encodes its default flags in the name.
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--aarch64-O2
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--x86_64-O2
mv $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--aarch64-gisel

# Same for llvm-opt-fuzzer
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-earlycse
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-simplifycfg
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-gvn
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-sccp

cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-loop_predication
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-guard_widening
cp $OUT/llvm-opt-fuzzer $OUT/llvm-opt-fuzzer--x86_64-loop_vectorize

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

build_corpus "llvm/test/Transforms/InstCombine/" "llvm-opt-fuzzer--x86_64-instcombine"
build_corpus "llvm/test/Transforms/EarlyCSE/" "llvm-opt-fuzzer--x86_64-earlycse"
build_corpus "llvm/test/Transforms/SimplifyCFG/" "llvm-opt-fuzzer--x86_64-simplifycfg"
build_corpus "llvm/test/Transforms/GVN/" "llvm-opt-fuzzer--x86_64-gvn"
build_corpus "llvm/test/Transforms/SCCP/" "llvm-opt-fuzzer--x86_64-sccp"

build_corpus "llvm/test/Transforms/LoopPredication/" "llvm-opt-fuzzer--x86_64-loop_predication"
build_corpus "llvm/test/Transforms/GuardWidening/" "llvm-opt-fuzzer--x86_64-guard_widening"
build_corpus "llvm/test/Transforms/LoopVectorize/" "llvm-opt-fuzzer--x86_64-loop_vectorize"

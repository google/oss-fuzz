#!/bin/bash -eu
# Copyright 2023 Google LLC
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
set euox pipefail

export LDFLAGS="-fuse-ld=lld"

declare -A LLVM_SANITIZER=( ["address"]="Address" ["undefined"]="Undefined" ["memory"]="Memory" )

if [[ -v LLVM_SANITIZER[$SANITIZER] ]]; then
  LLVM_SANITIZER_FLAG="-DLLVM_USE_SANITIZER=${LLVM_SANITIZER[$SANITIZER]}" 
else
  LLVM_SANITIZER_FLAG=""
fi

cmake -DCMAKE_BUILD_TYPE=Release \
        -DLLVM_ENABLE_PROJECTS="clang" \
        -DLLVM_TARGETS_TO_BUILD="X86" \
        $LLVM_SANITIZER_FLAG \
        -DLLVM_ENABLE_TERMINFO=OFF \
        -DLLVM_ENABLE_ASSERTIONS=ON \
        -DLLVM_ENABLE_EH=OFF \
        -DLLVM_ENABLE_RTTI=OFF \
        -DLLVM_BUILD_32_BITS=OFF \
        -DLLVM_INCLUDE_BENCHMARKS=OFF \
        -DLLVM_INCLUDE_EXAMPLES=OFF \
        -DLLVM_INCLUDE_TESTS=OFF \
        -DCMAKE_INSTALL_MODE=ABS_SYMLINK \
        -S $SRC/llvm-project/llvm -B $WORK/llvm-build
cmake --build $WORK/llvm-build -j$(nproc)
cmake --install $WORK/llvm-build --prefix $WORK/llvm-install

# Cleanup space so github runners don't run out of disk space.
rm -rf $WORK/llvm-build $SRC/llvm-project

export LLVM_DIR=$WORK/llvm-install

cmake -G Ninja  -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DTARGET_WEBASSEMBLY=OFF \
  -DWITH_TUTORIALS=OFF \
  -DWITH_UTILS=OFF \
  -DWITH_PYTHON_BINDINGS=OFF \
  -DWITH_TESTS=ON \
  -DWITH_TEST_AUTO_SCHEDULE=OFF \
  -DWITH_TEST_CORRECTNESS=OFF \
  -DWITH_TEST_ERROR=OFF \
  -DWITH_TEST_WARNING=OFF \
  -DWITH_TEST_PERFORMANCE=OFF \
  -DWITH_TEST_RUNTIME=OFF \
  -DWITH_TEST_GENERATOR=OFF \
  -DWITH_TEST_FUZZ=ON \
  -DBUILD_SHARED_LIBS=OFF

cmake --build ./build --target build_fuzz -j$(nproc)

cp ./build/test/fuzz/fuzz_* $OUT

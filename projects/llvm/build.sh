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
  llvm-demangle-fuzzer \
  llvm-dwarfdump-fuzzer \
  llvm-isel-fuzzer \
  llvm-special-case-list-fuzzer \
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
    -DCLANG_ENABLE_PROTO_FUZZER=ON \
    -DLLVM_USE_SANITIZER="${LLVM_SANITIZER}"
for fuzzer in "${FUZZERS[@]}"; do
  ninja $fuzzer
  cp bin/$fuzzer $OUT
done

# isel-fuzzer encodes its default flags in the name.
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--aarch64-O2
cp $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--x86_64-O2
mv $OUT/llvm-isel-fuzzer $OUT/llvm-isel-fuzzer--aarch64-gisel

#!/bin/bash
# Copyright 2021 Google Inc.
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

(
cd $SRC/llvm-project && mkdir build_x64_opt && cd build_x64_opt

if [ "$SANITIZER" = "address" ]
then
  LLVM_USE_SANITIZER=Address
else
  LLVM_USE_SANITIZER=""
fi

cmake \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_USE_SANITIZER=$LLVM_USE_SANITIZER \
    -DLLVM_ENABLE_PROJECTS="compiler-rt;clang;lld;lldb" \
    -DLLVM_USE_LINKER=lld \
    -DLLVM_TARGETS_TO_BUILD="X86" \
    -DLLVM_BUILD_TOOLS=OFF \
    -DLLVM_BUILD_UTILS=OFF \
    -DLLVM_BUILD_TESTS=OFF \
    -DLLVM_INCLUDE_TESTS=OFF \
    -DLLDB_ENABLE_PYTHON=0 \
    -DLLDB_INCLUDE_TESTS=OFF \
    -DCMAKE_INSTALL_PREFIX="$SRC/llvm" \
    -GNinja \
    ../llvm

ninja \
    install-clang \
    install-clang-headers \
    install-clang-libraries \
    install-liblldb \
    install-lld \
    install-lldb-headers \
    install-lldb-server \
    install-llvm-headers \
    install-llvm-libraries
)
export LLVM_INSTALL_PATH=$SRC/llvm

bazel_build_fuzz_tests

# OSS-Fuzz rule doesn't build data dependencies
bazel build //testdata:fuzzer_binary_gen

# OSS-Fuzz rule doesn't package runfiles yet:
# https://github.com/bazelbuild/rules_fuzzing/issues/100
mkdir -p $OUT/lldb_eval_libfuzzer_test.runfiles
# fuzzer_binary
mkdir -p $OUT/lldb_eval_libfuzzer_test.runfiles/lldb_eval/testdata
cp $SRC/lldb-eval/bazel-bin/testdata/fuzzer_binary $OUT/lldb_eval_libfuzzer_test.runfiles/lldb_eval/testdata/
cp $SRC/lldb-eval/testdata/fuzzer_binary.cc $OUT/lldb_eval_libfuzzer_test.runfiles/lldb_eval/testdata/
# lldb-server
mkdir -p $OUT/lldb_eval_libfuzzer_test.runfiles/llvm_project/bin
cp $SRC/llvm/bin/lldb-server $OUT/lldb_eval_libfuzzer_test.runfiles/llvm_project/bin/lldb-server

# OSS-Fuzz rule doesn't handle dynamic dependencies
# Copy liblldb.so and path RPATH of the fuzz target
mkdir -p $OUT/lib
cp -a $SRC/llvm/lib/liblldb.so* $OUT/lib
patchelf --set-rpath '$ORIGIN/lib' $OUT/lldb_eval_libfuzzer_test

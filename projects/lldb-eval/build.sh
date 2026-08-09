#!/bin/bash
# Copyright 2021 Google LLC
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
cd $SRC/
GITHUB_RELEASE="https://github.com/google/lldb-eval/releases/download/oss-fuzz-ubuntu-20.04"

if [ "$SANITIZER" = "address" ]
then
  LLVM_ARCHIVE="llvm-12.0.1-x86_64-linux-release-address.tar.gz"
elif [ "$SANITIZER" = "memory" ]
then
  LLVM_ARCHIVE="llvm-12.0.1-x86_64-linux-release-memory.tar.gz"
elif [ "$SANITIZER" = "undefined" ]
then
  LLVM_ARCHIVE="llvm-12.0.1-x86_64-linux-release.tar.gz"
elif [ "$SANITIZER" = "coverage" ]
then
  # For coverage we also need the original source code.
  wget --quiet $GITHUB_RELEASE/llvm-12.0.1-source.tar.gz
  tar -xzf llvm-12.0.1-source.tar.gz
  wget --quiet $GITHUB_RELEASE/llvm-12.0.1-x86_64-linux-release-genfiles.tar.gz
  tar -xzf llvm-12.0.1-x86_64-linux-release-genfiles.tar.gz

  LLVM_ARCHIVE="llvm-12.0.1-x86_64-linux-release.tar.gz"
else
  echo "Unknown sanitizer: $SANITIZER"
  exit 1
fi

wget --quiet $GITHUB_RELEASE/$LLVM_ARCHIVE
mkdir -p llvm && tar -xzf $LLVM_ARCHIVE --strip-components 1 -C llvm
)
export LLVM_INSTALL_PATH=$SRC/llvm

if [ "$SANITIZER" = "undefined" ]
then
  # Disable vptr because it's not allowed with '-fno-rtti'
  CFLAGS="$CFLAGS -fno-sanitize=function,vptr"
  CXXFLAGS="$CXXFLAGS -fno-sanitize=function,vptr"
fi

# Undefine NDEBUG to enable asserts.
export BAZEL_EXTRA_BUILD_FLAGS="--copt=-UNDEBUG"

# Run the build!
bazel_build_fuzz_tests

# OSS-Fuzz rule doesn't build data dependencies
bazel build //testdata:fuzzer_binary_gen

# OSS-Fuzz rule doesn't handle dynamic dependencies
# Copy liblldb.so
mkdir -p $OUT/lib
cp $SRC/llvm/lib/liblldb.so* $OUT/lib

# List of targets to fuzz.
TARGETS=(
  lldb_eval_libfuzzer_test
  lldb_vs_lldb_eval_libfuzzer_test
)

# Preparation of each target.
for target in ${TARGETS[@]}; do
  # OSS-Fuzz rule doesn't package runfiles yet:
  # https://github.com/bazelbuild/rules_fuzzing/issues/100
  mkdir -p $OUT/$target.runfiles
  # fuzzer_binary
  mkdir -p $OUT/$target.runfiles/lldb_eval/testdata
  cp $SRC/lldb-eval/bazel-bin/testdata/fuzzer_binary $OUT/$target.runfiles/lldb_eval/testdata/
  cp $SRC/lldb-eval/testdata/fuzzer_binary.cc $OUT/$target.runfiles/lldb_eval/testdata/
  # lldb-server
  mkdir -p $OUT/$target.runfiles/llvm_project/bin
  cp $SRC/llvm/bin/lldb-server $OUT/$target.runfiles/llvm_project/bin/lldb-server
  # Patch RPATH of the fuzz target
  patchelf --set-rpath '$ORIGIN/lib' $OUT/$target
done

cp $SRC/lldb_vs_lldb_eval_libfuzzer_test.options $OUT/

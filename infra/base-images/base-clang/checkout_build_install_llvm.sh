#!/bin/bash -eux
# Copyright 2016 Google Inc.
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

LLVM_DEP_PACKAGES="build-essential make cmake ninja-build git subversion python2.7"
apt-get install -y $LLVM_DEP_PACKAGES

# Checkout

# Use chromium's clang revision
mkdir $SRC/chromium_tools
cd $SRC/chromium_tools
git clone https://chromium.googlesource.com/chromium/src/tools/clang
cd clang

OUR_LLVM_REVISION=334100  # For manual bumping.
FORCE_OUR_REVISION=0  # To allow for manual downgrades.
LLVM_REVISION=$(grep -Po "CLANG_REVISION = '\K\d+(?=')" scripts/update.py)

if [ $OUR_LLVM_REVISION -gt $LLVM_REVISION ] || [ $FORCE_OUR_REVISION -ne 0 ]; then
  LLVM_REVISION=$OUR_LLVM_REVISION
fi

echo "Using LLVM revision: $LLVM_REVISION"

cd $SRC && svn co https://llvm.org/svn/llvm-project/llvm/trunk@$LLVM_REVISION llvm
cd $SRC/llvm/tools && svn co https://llvm.org/svn/llvm-project/cfe/trunk@$LLVM_REVISION clang
cd $SRC/llvm/projects && svn co https://llvm.org/svn/llvm-project/compiler-rt/trunk@$LLVM_REVISION compiler-rt
cd $SRC/llvm/projects && svn co https://llvm.org/svn/llvm-project/libcxx/trunk@$LLVM_REVISION libcxx
cd $SRC/llvm/projects && svn co https://llvm.org/svn/llvm-project/libcxxabi/trunk@$LLVM_REVISION libcxxabi

# Build & install
mkdir -p $WORK/llvm
cd $WORK/llvm
cmake -G "Ninja" \
      -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
      -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="X86" \
      $SRC/llvm
ninja
ninja install
rm -rf $WORK/llvm

mkdir -p $WORK/msan
cd $WORK/msan

# https://github.com/google/oss-fuzz/issues/1099
cat <<EOF > $WORK/msan/blacklist.txt
fun:__gxx_personality_*
EOF

cmake -G "Ninja" \
      -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DLLVM_USE_SANITIZER=Memory -DCMAKE_INSTALL_PREFIX=/usr/msan/ \
      -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
      -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="X86" \
      -DCMAKE_CXX_FLAGS="-fsanitize-blacklist=$WORK/msan/blacklist.txt" \
      $SRC/llvm
ninja cxx
ninja install-cxx
rm -rf $WORK/msan

# Pull trunk libfuzzer.
cd $SRC && svn co https://llvm.org/svn/llvm-project/compiler-rt/trunk/lib/fuzzer libfuzzer

cp $SRC/llvm/tools/sancov/coverage-report-server.py /usr/local/bin/

# Cleanup
rm -rf $SRC/llvm
rm -rf $SRC/chromium_tools
apt-get remove --purge -y $LLVM_DEP_PACKAGES
apt-get autoremove -y

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

LLVM_DEP_PACKAGES="build-essential make cmake ninja-build git python2.7"
apt-get install -y $LLVM_DEP_PACKAGES

# Checkout
cd /src && git clone --depth 1 http://llvm.org/git/llvm.git
cd /src/llvm/tools && git clone --depth 1 http://llvm.org/git/clang.git
cd /src/llvm/projects && git clone --depth 1 http://llvm.org/git/compiler-rt.git
cd /src/llvm/projects && git clone --depth 1 http://llvm.org/git/libcxx.git
cd /src/llvm/projects && git clone --depth 1 http://llvm.org/git/libcxxabi.git
cd /src/llvm/projects && git clone --depth 1 http://llvm.org/git/lld.git

# Build & Install
mkdir -p /work/llvm
cd /work/llvm
cmake -G "Ninja" \
      -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
      -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="X86" \
      /src/llvm
ninja
ninja install
rm -rf /work/llvm

# Copy libfuzzer sources
mkdir /src/libfuzzer
cp -r /src/llvm/lib/Fuzzer/* /src/libfuzzer/

# Cleanup
rm -rf /src/llvm
apt-get remove --purge -y $LLVM_DEP_PACKAGES
apt-get autoremove -y

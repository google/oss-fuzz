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

LLVM_DEP_PACKAGES="build-essential make cmake ninja-build git subversion python2.7 g++-multilib"
apt-get install -y $LLVM_DEP_PACKAGES

# Checkout
CHECKOUT_RETRIES=10
function checkout_with_retries {
  REPOSITORY=$1
  LOCAL_PATH=$2
  CHECKOUT_RETURN_CODE=1

  # Disable exit on error since we might encounter some failures while retrying.
  set +e
  for i in $(seq 1 $CHECKOUT_RETRIES); do
    rm -rf $LOCAL_PATH
    svn co $REPOSITORY $LOCAL_PATH
    CHECKOUT_RETURN_CODE=$?
    if [ $CHECKOUT_RETURN_CODE -eq 0 ]; then
      break
    fi
  done

  # Re-enable exit on error. If checkout failed, script will exit.
  set -e
  return $CHECKOUT_RETURN_CODE
}

# Use chromium's clang revision
mkdir $SRC/chromium_tools
cd $SRC/chromium_tools
git clone https://chromium.googlesource.com/chromium/src/tools/clang
cd clang

OUR_LLVM_REVISION=359254  # For manual bumping.
FORCE_OUR_REVISION=0  # To allow for manual downgrades.
LLVM_REVISION=$(grep -Po "CLANG_SVN_REVISION = '\K\d+(?=')" scripts/update.py)

if [ $OUR_LLVM_REVISION -gt $LLVM_REVISION ] || [ $FORCE_OUR_REVISION -ne 0 ]; then
  LLVM_REVISION=$OUR_LLVM_REVISION
fi

echo "Using LLVM revision: $LLVM_REVISION"

cd $SRC && checkout_with_retries https://llvm.org/svn/llvm-project/llvm/trunk@$LLVM_REVISION llvm
cd $SRC/llvm/tools && checkout_with_retries https://llvm.org/svn/llvm-project/cfe/trunk@$LLVM_REVISION clang
cd $SRC/llvm/projects && checkout_with_retries https://llvm.org/svn/llvm-project/compiler-rt/trunk@$LLVM_REVISION compiler-rt
cd $SRC/llvm/projects && checkout_with_retries https://llvm.org/svn/llvm-project/libcxx/trunk@$LLVM_REVISION libcxx
cd $SRC/llvm/projects && checkout_with_retries https://llvm.org/svn/llvm-project/libcxxabi/trunk@$LLVM_REVISION libcxxabi

# Build & install. We build clang in two stages because gcc can't build a
# static version of libcxxabi
# (see https://github.com/google/oss-fuzz/issues/2164).
mkdir -p $WORK/llvm-stage2 $WORK/llvm-stage1
cd $WORK/llvm-stage1

TARGET_TO_BUILD=
case $(uname -m) in
    x86_64)
        TARGET_TO_BUILD=X86
        ;;
    aarch64)
        TARGET_TO_BUILD=AArch64
        ;;
    *)
        echo "Error: unsupported target $(uname -m)"
        exit 1
        ;;
esac
cmake -G "Ninja" \
      -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON -DLIBCXXABI_ENABLE_SHARED=OFF \
      -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="$TARGET_TO_BUILD" \
      $SRC/llvm
ninja

cd $WORK/llvm-stage2
export CC=$WORK/llvm-stage1/bin/clang
export CXX=$WORK/llvm-stage1/bin/clang++
cmake -G "Ninja" \
      -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON -DLIBCXXABI_ENABLE_SHARED=OFF \
      -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="$TARGET_TO_BUILD" \
      $SRC/llvm
ninja
ninja install
rm -rf $WORK/llvm-stage1 $WORK/llvm-stage2

mkdir -p $WORK/i386
cd $WORK/i386
cmake -G "Ninja" \
      -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_INSTALL_PREFIX=/usr/i386/ -DLIBCXX_ENABLE_SHARED=OFF \
      -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="-m32" -DCMAKE_CXX_FLAGS="-m32" \
      -DLLVM_TARGETS_TO_BUILD="$TARGET_TO_BUILD" \
      $SRC/llvm

ninja cxx
ninja install-cxx
rm -rf $WORK/i386

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
      -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="$TARGET_TO_BUILD" \
      -DCMAKE_CXX_FLAGS="-fsanitize-blacklist=$WORK/msan/blacklist.txt" \
      $SRC/llvm
ninja cxx
ninja install-cxx
rm -rf $WORK/msan

# Pull trunk libfuzzer.
cd $SRC && svn co https://llvm.org/svn/llvm-project/compiler-rt/trunk/lib/fuzzer libfuzzer

# Cleanup
rm -rf $SRC/llvm
rm -rf $SRC/chromium_tools
apt-get remove --purge -y $LLVM_DEP_PACKAGES
apt-get autoremove -y

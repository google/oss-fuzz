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
  if [ -d $LOCAL_PATH ]; then
    return 0
  fi

  # Disable exit on error since we might encounter some failures while retrying.
  set +e
  for i in $(seq 1 $CHECKOUT_RETRIES); do
    rm -rf $LOCAL_PATH
    git clone $REPOSITORY $LOCAL_PATH
    CHECKOUT_RETURN_CODE=$?
    if [ $CHECKOUT_RETURN_CODE -eq 0 ]; then
      break
    fi
  done

  # Re-enable exit on error. If checkout failed, script will exit.
  set -e
  return $CHECKOUT_RETURN_CODE
}

cd $SRC && checkout_with_retries https://github.com/llvm/llvm-project.git llvm-project
cd $SRC/llvm-project

# Build & install. We build clang in two stages because gcc can't build a
# static version of libcxxabi
# (see https://github.com/google/oss-fuzz/issues/2164).
mkdir -p $WORK/llvm-stage2

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

cd $WORK/llvm-stage2
cmake -G "Ninja" \
      -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON -DLIBCXXABI_ENABLE_SHARED=OFF \
      -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS="libcxx;libcxxabi;compiler-rt;clang" \
      -DLLVM_TARGETS_TO_BUILD="$TARGET_TO_BUILD" \
      $SRC/llvm-project/llvm

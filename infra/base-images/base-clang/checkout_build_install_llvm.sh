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

NPROC=16  # See issue #4270. The compiler crashes on GCB instance with 32 vCPUs.

LLVM_DEP_PACKAGES="build-essential make cmake ninja-build git python3 g++-multilib binutils-dev"
apt-get install -y $LLVM_DEP_PACKAGES

# Checkout
CHECKOUT_RETRIES=10
function clone_with_retries {
  REPOSITORY=$1
  LOCAL_PATH=$2
  CHECKOUT_RETURN_CODE=1

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

function cmake_llvm {
  extra_args="$@"
  cmake -G "Ninja" \
      -DLIBCXX_ENABLE_SHARED=OFF \
      -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
      -DLIBCXXABI_ENABLE_SHARED=OFF \
      -DCMAKE_BUILD_TYPE=Release \
      -DLLVM_TARGETS_TO_BUILD="$TARGET_TO_BUILD" \
      -DLLVM_ENABLE_PROJECTS="$PROJECTS_TO_BUILD" \
      -DLLVM_BINUTILS_INCDIR="/usr/include/" \
      $extra_args \
      $LLVM_SRC/llvm
}

# Use chromium's clang revision
mkdir $SRC/chromium_tools
cd $SRC/chromium_tools
git clone https://chromium.googlesource.com/chromium/src/tools/clang
cd clang

LLVM_SRC=$SRC/llvm-project

# For manual bumping.
OUR_LLVM_REVISION=llvmorg-12-init-17251-g6de48655

# To allow for manual downgrades. Set to 0 to use Chrome's clang version (i.e.
# *not* force a manual downgrade). Set to 1 to force a manual downgrade.
FORCE_OUR_REVISION=1
LLVM_REVISION=$(grep -Po "CLANG_REVISION = '\K([^']+)" scripts/update.py)

clone_with_retries https://github.com/llvm/llvm-project.git $LLVM_SRC

set +e
git -C $LLVM_SRC merge-base --is-ancestor $OUR_LLVM_REVISION $LLVM_REVISION
IS_OUR_REVISION_ANCESTOR_RETCODE=$?
set -e

# Use our revision if specified by FORCE_OUR_REVISION or if our revision is a
# later revision than Chrome's (i.e. not an ancestor of Chrome's).
if [ $IS_OUR_REVISION_ANCESTOR_RETCODE -ne 0 ] || [ $FORCE_OUR_REVISION -eq 1 ] ; then
  LLVM_REVISION=$OUR_LLVM_REVISION
fi

git -C $LLVM_SRC checkout $LLVM_REVISION
echo "Using LLVM revision: $LLVM_REVISION"

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

PROJECTS_TO_BUILD="libcxx;libcxxabi;compiler-rt;clang;lld"

cmake_llvm
ninja -j $NPROC

cd $WORK/llvm-stage2
export CC=$WORK/llvm-stage1/bin/clang
export CXX=$WORK/llvm-stage1/bin/clang++
cmake_llvm
ninja -j $NPROC
ninja install
rm -rf $WORK/llvm-stage1 $WORK/llvm-stage2

# Use the clang we just built from now on.
CMAKE_EXTRA_ARGS="-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++"

# 32-bit libraries.
mkdir -p $WORK/i386
cd $WORK/i386
cmake_llvm $CMAKE_EXTRA_ARGS \
    -DCMAKE_INSTALL_PREFIX=/usr/i386/ \
    -DCMAKE_C_FLAGS="-m32" \
    -DCMAKE_CXX_FLAGS="-m32"

ninja -j $NPROC cxx
ninja install-cxx
rm -rf $WORK/i386

# MemorySanitizer instrumented libraries.
mkdir -p $WORK/msan
cd $WORK/msan

# https://github.com/google/oss-fuzz/issues/1099
cat <<EOF > $WORK/msan/blocklist.txt
fun:__gxx_personality_*
EOF

cmake_llvm $CMAKE_EXTRA_ARGS \
    -DLLVM_USE_SANITIZER=Memory \
    -DCMAKE_INSTALL_PREFIX=/usr/msan/ \
    -DCMAKE_CXX_FLAGS="-fsanitize-blacklist=$WORK/msan/blocklist.txt"

ninja -j $NPROC cxx
ninja install-cxx
rm -rf $WORK/msan

# DataFlowSanitizer instrumented libraries.
mkdir -p $WORK/dfsan
cd $WORK/dfsan

cmake_llvm $CMAKE_EXTRA_ARGS \
    -DLLVM_USE_SANITIZER=DataFlow \
    -DCMAKE_INSTALL_PREFIX=/usr/dfsan/

ninja -j $NPROC cxx cxxabi
ninja install-cxx install-cxxabi
rm -rf $WORK/dfsan

# libFuzzer sources.
cp -r $LLVM_SRC/compiler-rt/lib/fuzzer $SRC/libfuzzer

# Cleanup
rm -rf $LLVM_SRC
rm -rf $SRC/chromium_tools
apt-get remove --purge -y $LLVM_DEP_PACKAGES
apt-get autoremove -y

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

# See issue #4270. The compiler crashes on GCB instance with 32 vCPUs, so when
# we compile on GCB we want 16 cores. But locally we want more (so use nproc /
# 2).
NPROC=$(expr $(nproc) / 2)

# zlib1g-dev is needed for llvm-profdata to handle coverage data from rust compiler
LLVM_DEP_PACKAGES="build-essential make cmake ninja-build git python3 python3-distutils g++-multilib binutils-dev zlib1g-dev"
apt-get update && apt-get install -y $LLVM_DEP_PACKAGES --no-install-recommends

INTROSPECTOR_DEP_PACKAGES="texinfo bison flex"
if [ -n "$INTROSPECTOR_PATCHES" ]; then
  apt-get install -y $INTROSPECTOR_DEP_PACKAGES
fi

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
# Pin clang due to https://github.com/google/oss-fuzz/issues/7617
git checkout 946a41a51f44207941b3729a0733dfc1e236644e

LLVM_SRC=$SRC/llvm-project

# For manual bumping.
OUR_LLVM_REVISION=llvmorg-14-init-7378-gaee49255

# To allow for manual downgrades. Set to 0 to use Chrome's clang version (i.e.
# *not* force a manual downgrade). Set to 1 to force a manual downgrade.
# DO NOT CHANGE THIS UNTIL https://github.com/google/oss-fuzz/issues/7273 is
# RESOLVED.
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

if [ -n "$INTROSPECTOR_PATCHES" ]; then
  # For fuzz introspector.
  echo "Applying introspector changes"
  OLD_WORKING_DIR=$PWD
  cd $LLVM_SRC
  cp -rf /fuzz-introspector/llvm/include/llvm/Transforms/FuzzIntrospector/ ./llvm/include/llvm/Transforms/FuzzIntrospector
  cp -rf /fuzz-introspector/llvm/lib/Transforms/FuzzIntrospector ./llvm/lib/Transforms/FuzzIntrospector

  # LLVM currently does not support dynamically loading LTO passes. Thus,
  # we hardcode it into Clang instead.
  # Ref: https://reviews.llvm.org/D77704
  /fuzz-introspector/sed_cmds.sh
  cd $OLD_WORKING_DIR
fi

# Build & install.
mkdir -p $WORK/llvm-stage2 $WORK/llvm-stage1
python3 $SRC/chromium_tools/clang/scripts/update.py --output-dir $WORK/llvm-stage1

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

cd $WORK/llvm-stage2
export CC=$WORK/llvm-stage1/bin/clang
export CXX=$WORK/llvm-stage1/bin/clang++
cmake_llvm
ninja -j $NPROC
ninja install
rm -rf $WORK/llvm-stage1 $WORK/llvm-stage2

# Use the clang we just built from now on.
CMAKE_EXTRA_ARGS="-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++"

function cmake_libcxx {
  extra_args="$@"
  cmake -G "Ninja" \
      -DLIBCXX_ENABLE_SHARED=OFF \
      -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=ON \
      -DLIBCXXABI_ENABLE_SHARED=OFF \
      -DCMAKE_BUILD_TYPE=Release \
      -DLLVM_TARGETS_TO_BUILD="$TARGET_TO_BUILD" \
      -DLLVM_ENABLE_PROJECTS="libcxx;libcxxabi" \
      -DLLVM_BINUTILS_INCDIR="/usr/include/" \
      $extra_args \
      $LLVM_SRC/llvm
}

# 32-bit libraries.
mkdir -p $WORK/i386
cd $WORK/i386
cmake_libcxx $CMAKE_EXTRA_ARGS \
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

cmake_libcxx $CMAKE_EXTRA_ARGS \
    -DLLVM_USE_SANITIZER=Memory \
    -DCMAKE_INSTALL_PREFIX=/usr/msan/ \
    -DCMAKE_CXX_FLAGS="-fsanitize-blacklist=$WORK/msan/blocklist.txt"

ninja -j $NPROC cxx
ninja install-cxx
rm -rf $WORK/msan

# DataFlowSanitizer instrumented libraries.
mkdir -p $WORK/dfsan
cd $WORK/dfsan

cmake_libcxx $CMAKE_EXTRA_ARGS \
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
if [ -n "$INTROSPECTOR_PATCHES" ]; then
  apt-get remove --purge -y $INTROSPECTOR_DEP_PACKAGES
fi
apt-get autoremove -y

# Delete unneeded parts of LLVM to reduce image size.
# See https://github.com/google/oss-fuzz/issues/5170
LLVM_TOOLS_TMPDIR=/tmp/llvm-tools
mkdir $LLVM_TOOLS_TMPDIR
# Move binaries with llvm- prefix that we want into LLVM_TOOLS_TMPDIR
mv \
  /usr/local/bin/llvm-ar \
  /usr/local/bin/llvm-as \
  /usr/local/bin/llvm-config \
  /usr/local/bin/llvm-cov \
  /usr/local/bin/llvm-objcopy \
  /usr/local/bin/llvm-nm \
  /usr/local/bin/llvm-profdata \
  /usr/local/bin/llvm-ranlib \
  /usr/local/bin/llvm-symbolizer \
  /usr/local/bin/llvm-undname \
  $LLVM_TOOLS_TMPDIR
# Delete remaining llvm- binaries.
rm -rf /usr/local/bin/llvm-*
# Restore the llvm- binaries we want to keep.
mv $LLVM_TOOLS_TMPDIR/* /usr/local/bin/
rm -rf $LLVM_TOOLS_TMPDIR

# Remove binaries from LLVM build that we don't need.
rm -f \
  /usr/local/bin/bugpoint \
  /usr/local/bin/llc \
  /usr/local/bin/lli \
  /usr/local/bin/clang-check \
  /usr/local/bin/clang-refactor \
  /usr/local/bin/clang-offload-wrapper \
  /usr/local/bin/clang-offload-bundler \
  /usr/local/bin/clang-check \
  /usr/local/bin/clang-refactor \
  /usr/local/bin/c-index-test \
  /usr/local/bin/clang-rename \
  /usr/local/bin/clang-scan-deps \
  /usr/local/bin/clang-extdef-mapping \
  /usr/local/bin/diagtool \
  /usr/local/bin/sanstats \
  /usr/local/bin/dsymutil \
  /usr/local/bin/verify-uselistorder \
  /usr/local/bin/clang-format

# Remove unneeded clang libs, CMake files from LLVM build, lld libs, and the
# libraries.
# Note: we need fuzzer_no_main libraries for atheris. Don't delete.
rm -rf \
  /usr/local/lib/libclang* \
  /usr/local/lib/liblld* \
  /usr/local/lib/cmake/

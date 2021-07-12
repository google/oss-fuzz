#!/bin/bash -eu
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


function synch_dependency_to_commit() {
  # Utility function to synch a dependency to a specific commit. Takes two arguments:
  #   - $1: folder of the dependency's git repository
  #   - $2: path to the text file containing the desired commit hash
  if [ "$FETCH_DEPENDENCIES" = false ] ; then
    return
  fi
  DEP_REV=$(sed 's/Subproject commit //' "$2")
  pushd "$1"
  git fetch
  # Disable git warning about detached head when checking out a specific commit.
  git -c advice.detachedHead=false checkout "$DEP_REV"
  popd
}


function detect_platform() {
  unameOut="$(uname -s)"
  case "${unameOut}" in
      Linux*)     PLATFORM=Linux;;
      Darwin*)    PLATFORM=Mac;;
      *)          PLATFORM="UNKNOWN:${unameOut}"
  esac
  echo -e "${COLOR_GREEN}Detected platform: $PLATFORM ${COLOR_OFF}"
}

function setup_fmt() {
  FMT_DIR=$DEPS_DIR/fmt
  FMT_BUILD_DIR=$DEPS_DIR/fmt/build/

  if [ ! -d "$FMT_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning fmt repo ${COLOR_OFF}"
    git clone https://github.com/fmtlib/fmt.git  "$FMT_DIR"
  fi
  cd "$FMT_DIR"
  git fetch --tags
  git checkout 6.2.1
  echo -e "${COLOR_GREEN}Building fmt ${COLOR_OFF}"
  mkdir -p "$FMT_BUILD_DIR"
  cd "$FMT_BUILD_DIR" || exit

  cmake                                           \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"               \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"            \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo             \
    "$MAYBE_OVERRIDE_CXX_FLAGS"                   \
    -DFMT_DOC=OFF                                 \
    -DFMT_TEST=OFF                                \
    ..
  make -j4
  make install
  echo -e "${COLOR_GREEN}fmt is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

function setup_googletest() {
  GTEST_DIR=$DEPS_DIR/googletest
  GTEST_BUILD_DIR=$DEPS_DIR/googletest/build/

  if [ ! -d "$GTEST_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning googletest repo ${COLOR_OFF}"
    git clone https://github.com/google/googletest.git  "$GTEST_DIR"
  fi
  cd "$GTEST_DIR"
  git fetch --tags
  git checkout release-1.8.0
  echo -e "${COLOR_GREEN}Building googletest ${COLOR_OFF}"
  mkdir -p "$GTEST_BUILD_DIR"
  cd "$GTEST_BUILD_DIR" || exit

  cmake                                           \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"               \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"            \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo             \
    ..
  make -j4
  make install
  echo -e "${COLOR_GREEN}googletest is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

function setup_folly() {
  FOLLY_DIR=$DEPS_DIR/folly
  FOLLY_BUILD_DIR=$DEPS_DIR/folly/build/

  if [ ! -d "$FOLLY_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning folly repo ${COLOR_OFF}"
    git clone https://github.com/facebook/folly.git "$FOLLY_DIR"
  fi
  #synch_dependency_to_commit "$FOLLY_DIR" "$BASE_DIR"/../build/deps/github_hashes/facebook/folly-rev.txt
  if [ "$PLATFORM" = "Mac" ]; then
    # Homebrew installs OpenSSL in a non-default location on MacOS >= Mojave
    # 10.14 because MacOS has its own SSL implementation.  If we find the
    # typical Homebrew OpenSSL dir, load OPENSSL_ROOT_DIR so that cmake
    # will find the Homebrew version.
    dir=/usr/local/opt/openssl
    if [ -d $dir ]; then
        export OPENSSL_ROOT_DIR=$dir
    fi
  fi
  echo -e "${COLOR_GREEN}Building Folly ${COLOR_OFF}"
  mkdir -p "$FOLLY_BUILD_DIR"
  cd "$FOLLY_BUILD_DIR" || exit
  MAYBE_DISABLE_JEMALLOC=""
  if [ "$NO_JEMALLOC" == true ] ; then
    MAYBE_DISABLE_JEMALLOC="-DFOLLY_USE_JEMALLOC=0"
  fi

  MAYBE_USE_STATIC_DEPS=""
  MAYBE_USE_STATIC_BOOST=""
  MAYBE_BUILD_SHARED_LIBS=""
  if [ "$BUILD_FOR_FUZZING" == true ] ; then
    MAYBE_USE_STATIC_DEPS="-DUSE_STATIC_DEPS_ON_UNIX=ON"
    MAYBE_USE_STATIC_BOOST="-DBOOST_LINK_STATIC=ON"
    MAYBE_BUILD_SHARED_LIBS="-DBUILD_SHARED_LIBS=OFF"
  fi

  cmake                                           \
    -DCMAKE_PREFIX_PATH="$DEPS_DIR"               \
    -DCMAKE_INSTALL_PREFIX="$DEPS_DIR"            \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo             \
    -DBUILD_TESTS=OFF                             \
    "$MAYBE_USE_STATIC_DEPS"                      \
    "$MAYBE_USE_STATIC_BOOST"                     \
    "$MAYBE_BUILD_SHARED_LIBS"                    \
    "$MAYBE_OVERRIDE_CXX_FLAGS"                   \
    $MAYBE_DISABLE_JEMALLOC                       \
    ..
  make -j "$JOBS"
  make install
  echo -e "${COLOR_GREEN}Folly is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}



# Main installation steps
mkdir $SRC/folly-fuzz
cd $SRC/folly-fuzz

# Link to, and copy over, libunwind
# We need to link to libunwind to ensure exception handling works
# See https://clang.llvm.org/docs/Toolchain.html#unwind-library
export LDFLAGS="-lunwind"
mkdir -p $OUT/lib
cp /usr/lib/x86_64-linux-gnu/libunwind.so.8 $OUT/lib/

# Obtain the base directory this script resides in.
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Useful constants
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_OFF="\033[0m"

INSTALL_DEPENDENCIES=false
FETCH_DEPENDENCIES=true

MAYBE_OVERRIDE_CXX_FLAGS=""
NO_JEMALLOC=true
BUILD_FOR_FUZZING=true

JOBS=4
detect_platform

BUILD_DIR=$PWD
#BUILD_DIR=_build
#mkdir -p $BUILD_DIR

set -e nounset
trap 'cd $BASE_DIR' EXIT
cd $BUILD_DIR || exit
BWD=$(pwd)
DEPS_DIR=$BWD/deps
mkdir -p "$DEPS_DIR"

# Must execute from the directory containing this script
cd "$(dirname "$0")"


setup_fmt
setup_googletest
setup_folly

#cd $SRC/proxygen
#find . -name "*.a"

#cd $SRC/proxygen/_build/deps

cd ${BWD}/deps
cp $SRC/fuzz_json_parse.cpp .
cp $SRC/fuzz_ip_addr.cpp .

static_libd=($(find /usr/lib -name "libdouble-conversion.a"))
static_boostregex=($(find /usr -name "libboost_regex.a"))
static_filesystem=($(find /usr -name "libboost_filesystem.a"))
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_json_parse.cpp ./lib/libfolly.a ./lib/libfmt.a \
    -I./folly -I./folly/build/ ${static_libd} ${static_boostregex} ${static_filesystem} \
    ./googletest/build/googlemock/libgmock.a ./lib/libgmock.a -lglog -lgflags -liberty \
    -o $OUT/fuzz_json_parse

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_ip_addr.cpp ./lib/libfolly.a ./lib/libfmt.a \
    -I./folly -I./folly/build/ ${static_libd} ${static_boostregex} ${static_filesystem} \
    ./googletest/build/googlemock/libgmock.a ./lib/libgmock.a -lglog -lgflags -liberty \
    -o $OUT/fuzz_ip_addr

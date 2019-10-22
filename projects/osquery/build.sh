#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

PROJECT=osquery

# Move the project content into the current overlay.
# CMake builtin 'rename' will attempt a hardlink.
( cd / &&\
  mv "${SRC}/${PROJECT}" "${SRC}/${PROJECT}-dev" &&\
  mv "${SRC}/${PROJECT}-dev" "${SRC}/${PROJECT}" )

pushd "${SRC}/${PROJECT}"
mkdir build && pushd build

export CXXFLAGS="${CXXFLAGS} -Wl,-lunwind -Wl,-lc++abi"
export CFLAGS="${CFLAGS} -Wl,-lunwind"

cmake \
  -DOSQUERY_VERSION:string=0.0.0-fuzz \
  -DOSQUERY_ENABLE_ADDRESS_SANITIZER:BOOL=ON \
  -DOSQUERY_ENABLE_FUZZER_SANITIZERS:BOOL=ON \
  -DOSQUERY_TOOLCHAIN_SYSROOT=/usr/local/osquery-toolchain \
  ..
cmake \
  -DCMAKE_EXE_LINKER_FLAGS=${LIB_FUZZING_ENGINE} \
  ..

# Build harnesses
cmake --build . -j$(nproc) --target osqueryfuzz-config

# Cleanup
find . -type f -name '*.o' -delete
rm -rf "${SRC}/${PROJECT}/libraries/cmake/source/libudev/src/test"
rm -rf libs/src/patched-source/libudev/src/test

# Move harnesses to output path
cp osquery/main/harnesses/osqueryfuzz-config "${OUT}/osqueryfuzz-config"

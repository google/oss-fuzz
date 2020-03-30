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

cd $SRC/iroha
./vcpkg/oss/build_deps.sh
./clean.sh
mkdir build
cd build

export ASAN_OPTIONS=detect_leaks=0
SANITIZER_FLAGS_VAR=SANITIZER_FLAGS_${SANITIZER}
export CFLAGS="$CFLAGS ${!SANITIZER_FLAGS_VAR}"
export CXXFLAGS="$CXXFLAGS ${!SANITIZER_FLAGS_VAR}"
export LDFLAGS="${!SANITIZER_FLAGS_VAR}"

$CMAKE -DCMAKE_TOOLCHAIN_FILE=/tmp/vcpkg/scripts/buildsystems/vcpkg.cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DFUZZING_ONLY=ON ..
make fuzzing
  
cp test_bin/* $OUT/

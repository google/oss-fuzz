#!/bin/bash -eu
# Copyright 2025 Google LLC
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

apt-get update
apt-get install -y build-essential ninja-build cmake make \
                   zlib1g-dev libreadline-dev libunwind-dev

: ${LD:="${CXX}"}
: ${LDFLAGS:="${CXXFLAGS}"}  # to make sure we link with sanitizer runtime

patch -p1 < lua-c-api-tests/patches/luajit-v2.1.patch

# Build the target project.
make CC="${CC}" CFLAGS="${CFLAGS} -DLUAJIT_USE_ASAN -DLUA_USE_ASSERT -DLUA_USE_APICHECK" \
     LDFLAGS="${LDFLAGS}" HOST_CFLAGS=-fno-sanitize=undefined -C src
LUA_LIBRARIES=$(realpath ./src/libluajit.a)
LUA_INCLUDE_DIR=$(realpath ./src/)
LUA_EXECUTABLE=$(realpath ./src/luajit)

# Build the tests.
cd lua-c-api-tests
cmake -S . -B build -DCMAKE_C_COMPILER="${CC}" \
  -DCMAKE_CXX_COMPILER="${CXX}" \
  -DIS_LUAJIT=TRUE \
  -DLUA_INCLUDE_DIR="${LUA_INCLUDE_DIR}" \
  -DLUA_LIBRARIES="${LUA_LIBRARIES}" \
  -DLUA_EXECUTABLE="${LUA_EXECUTABLE}" \
  -DLUA_VERSION_STRING=\"luajit2\"
cmake --build build --parallel

for f in $(find build/tests/ -name '*_test' -type f);
do
  cp $f $OUT/
done

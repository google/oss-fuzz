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

cp $SRC/s2_fuzzer.cc $SRC/s2geometry/src/
export CXXFLAGS="${CXXFLAGS} -std=c++17"

cd $SRC/
git clone --depth=1 https://github.com/abseil/abseil-cpp
cd abseil-cpp
mkdir build && cd build
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON ../  && make && make install

cd $SRC/s2geometry
git apply  --ignore-space-change --ignore-whitespace $SRC/project.patch
mkdir build && cd build

cmake -DBUILD_SHARED_LIBS=OFF \
      -DABSL_MIN_LOG_LEVEL=4 ..
make -j$(nproc)
find . -name "s2fuzzer" -exec cp {} $OUT/s2_fuzzer \;

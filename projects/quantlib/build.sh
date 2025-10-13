#!/bin/bash -eu
# Copyright 2023 Google LLC
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

# Install Boost headers
cd $SRC/
tar jxf boost_1_87_0.tar.bz2
cd boost_1_87_0/
CFLAGS="" CXXFLAGS="" ./bootstrap.sh
CFLAGS="" CXXFLAGS="" ./b2 headers
./b2 --with-math install

cd $SRC/quantlib

mkdir build
cd build
export LDFLAGS="-Wl,-rpath,'\$ORIGIN/lib'"
cmake .. -GNinja\
 -DBOOST_ROOT=/usr\
 -DCMAKE_BUILD_TYPE=Release\
 -DQL_COMPILE_WARNING_AS_ERROR=ON\
 -DQL_BUILD_FUZZ_TEST_SUITE=ON\
 -DQL_BUILD_TEST_SUITE=OFF\
 -DQL_BUILD_BENCHMARK=OFF\
 -DQL_BUILD_EXAMPLES=OFF\
 -DCMAKE_CXX_STANDARD=20\
 -L
cmake --build . --verbose -j$(nproc)
mkdir $OUT/lib -p
cp ql/libQuantLib.so* $OUT/lib/
find fuzz-test-suite -executable -type f -exec cp {} $OUT \;

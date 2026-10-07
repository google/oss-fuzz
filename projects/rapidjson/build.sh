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

export CXXFLAGS="${CXXFLAGS} -pthread"

if [[ $CFLAGS = *sanitize=memory* ]]
then
    export CXXFLAGS="$CXXFLAGS -DMSAN"
fi

if [[ $CFLAGS = *sanitize=address* ]]
then
    export CXXFLAGS="$CXXFLAGS -DASAN"
fi

# Build fuzz harness.
$CXX $CXXFLAGS -D_GLIBCXX_DEBUG -I $SRC/rapidjson/include $SRC/fuzzer.cpp $LIB_FUZZING_ENGINE -o $OUT/fuzzer

# Build unit test and perf test only
mkdir build
cd build
NO_ERROR="-Wno-error=character-conversion"
NO_ERROR="$NO_ERROR -Wno-error=deprecated-declarations"
NO_ERROR="$NO_ERROR -Wno-error=uninitialized-const-pointer"
export LDFLAGS="-pthread"
cmake -DRAPIDJSON_BUILD_CXX17=ON \
  -DRAPIDJSON_BUILD_CXX11=OFF \
  -DRAPIDJSON_BUILD_THIRDPARTY_GTEST=OFF \
  -DCMAKE_CXX_FLAGS="$NO_ERROR" \
  ..
make -j$(nproc) unittest perftest

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

# First build library and tests, which is needed for OSS-Fuzz's Chronos.
mkdir build
cd build
cmake ../
make -j$(nproc)
cd ../

# Build fuzz harness.
$CXX $CXXFLAGS -D_GLIBCXX_DEBUG -I $SRC/rapidjson/include $SRC/fuzzer.cpp $LIB_FUZZING_ENGINE -o $OUT/fuzzer


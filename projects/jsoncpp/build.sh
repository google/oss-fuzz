#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

mkdir -p build
cd build
cmake -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      -DBUILD_SHARED_LIBS=OFF -G "Unix Makefiles" ..
make

# Compile fuzzer.
$CXX $CXXFLAGS -I../include $LIB_FUZZING_ENGINE \
    ../src/test_lib_json/fuzz.cpp -o $OUT/jsoncpp_fuzzer \
    src/lib_json/libjsoncpp.a

# Add dictionary.
cp $SRC/jsoncpp/src/test_lib_json/fuzz.dict $OUT/jsoncpp_fuzzer.dict

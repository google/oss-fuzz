#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# build project
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DURIPARSER_BUILD_DOCS:BOOL=OFF -DBUILD_SHARED_LIBS:BOOL=OFF -DURIPARSER_BUILD_TESTS:BOOL=OFF ..
make
make install

# build fuzzers
for fuzzers in $(find $SRC -name '*_fuzzer.cc'); do
  fuzz_basename=$(basename -s .cc $fuzzers)
  $CXX $CXXFLAGS -std=c++11 -I. \
  $fuzzers $LIB_FUZZING_ENGINE ./liburiparser.a  \
  -o $OUT/$fuzz_basename
done

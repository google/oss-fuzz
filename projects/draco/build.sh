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
# e.g.
# ./autogen.sh
# ./configure
# make -j$(nproc) all

# build fuzzers
# e.g.
# $CXX $CXXFLAGS -std=c++11 -Iinclude \
#     /path/to/name_of_fuzzer.cc -o $OUT/name_of_fuzzer \
#     $LIB_FUZZING_ENGINE /path/to/library.a

mkdir /fuzzing && cd /fuzzing
git clone https://github.com/google/draco
git clone https://github.com/google/security-research-pocs
mkdir draco/build
cd /fuzzing/draco/build
cmake ..
make

$CXX -I../../ -I../src -I./ -std=c++11 $CXXFLAGS $LDFLAGS -o fuzzer \
  /fuzzing/security-research-pocs/autofuzz/draco_decoder_fuzzer.cc \
  libdraco.a -lFuzzer

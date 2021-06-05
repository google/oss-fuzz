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
cd upb/cmake
cmake .
make -j$(nproc)

# use bazel to build instead ?
$CC $CFLAGS -I. -I.. -o descriptor.upb.o -c google/protobuf/descriptor.upb.c
$CXX $CXXFLAGS -DHAVE_FUZZER=1 -std=c++11 -I. -I.. -o fuzz_parsenew.o -c ../tests/file_descriptor_parsenew_fuzzer.cc
$CXX $CXXFLAGS fuzz_parsenew.o descriptor.upb.o -o $OUT/fuzz_parsenew *.a $LIB_FUZZING_ENGINE

# builds corpus
cd ..
find . -name "*.proto" | xargs zip -r $OUT/fuzz_parsenew_seed_corpus.zip

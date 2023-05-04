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

mkdir build
cd build
cmake ../
make

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I/src/highwayhash \
  CMakeFiles/nanobenchmark.dir/highwayhash/instruction_sets.cc.o \
  CMakeFiles/nanobenchmark.dir/highwayhash/os_specific.cc.o \
    ../highwayhash/highwayhash_fuzzer.cc \
    libhighwayhash.a -lpthread \
    -o $OUT/highwayhash_fuzzer

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I/src/highwayhash \
    ../highwayhash/sip_hash_fuzzer.cc \
    libhighwayhash.a -lpthread \
    -o $OUT/sip_hash_fuzzer

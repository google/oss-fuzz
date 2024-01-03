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

cd $SRC/libyuv
mkdir build
cd build
cmake   -DCMAKE_BUILD_TYPE=Debug ../

make clean
make -j$(nproc) all

$CXX $CXXFLAGS -I ../include/ -I ../../ \
    $SRC/libyuv_fuzzer.cc $SRC/fuzz_common.cc  -o $OUT/libyuv_fuzzer\
    $LIB_FUZZING_ENGINE ./libyuv.a

cp  $SRC/*.options $OUT/

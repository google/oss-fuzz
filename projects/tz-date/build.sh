#!/bin/bash -eu
# Copyright 2021 Google Inc.
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

mkdir build && cd build
cmake -DBUILD_TZ_LIB=ON ..
cmake --build .
$CXX $CXXFLAGS -DONLY_C_LOCALE=0 \
     -DUSE_OS_TZDB=0 \
     -I/src/date/include/date \
     -std=gnu++17 -std=c++17 \
     -o parse_fuzzer.o -c $SRC/parse_fuzzer.cpp

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    parse_fuzzer.o -std=c++17 -o \
    $OUT/parse_fuzzer libdate-tz.a

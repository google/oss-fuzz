#!/bin/bash -eu
# Copyright 2019 Google LLC
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

cd $SRC/myanmar-tools/clients/cpp
mkdir build
cd build
cmake -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON ..
make all

# Note: don't use the myanmartools_fuzz CMake target directly because we want
# to link with LIB_FUZZING_ENGINE instead of the default fuzzer.
# Copy the .so file to $OUT as well as the executable.
mkdir -p $OUT/lib
cp libmyanmartools.so $OUT/lib
# TODO(https://github.com/google/oss-fuzz/issues/2947): Link in libunwind
# statically or stop copying if ClusterFuzz bot images get libunwind.
# Copy libunwind since it isn't on the ClusterFuzz bot images.
cp /usr/lib/x86_64-linux-gnu/libunwind.so.8 $OUT/lib/
$CXX $CXXFLAGS -std=c++11 -I../public -L$OUT/lib \
    -Wl,-rpath,'$ORIGIN/lib' -lmyanmartools -lunwind \
    -o $OUT/zawgyi_detector_fuzz_target \
    ../zawgyi_detector_fuzz_target.cpp \
    $LIB_FUZZING_ENGINE

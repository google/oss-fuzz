#!/bin/bash -eu
# Copyright 2021 Google LLC
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

sed -i '34 a $ENV{CXXFLAGS}' CMakeLists.txt
mkdir -p build-dir && cd build-dir
cmake -DCMAKE_BUILD_TYPE="release" -DMUDUO_BUILD_EXAMPLES=OFF \
      ..
make -j$(nproc)

$CXX $CXXFLAGS -I/src/muduo \
	-o muduo_http_fuzzer.o \
    -c $SRC/muduo_http_fuzzer.cpp

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
	muduo_http_fuzzer.o \
    -o $OUT/muduo_http_fuzzer \
	./lib/libmuduo_http.a \
	./lib/libmuduo_net.a \
	./lib/libmuduo_base.a 

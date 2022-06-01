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

mkdir cmake-build
cd cmake-build
cmake -DBUILD_SHARED_LIBS=OFF \
      -DENABLE_TESTS=OFF \
      ..
make -j$(nproc)

$CXX $CXXFLAGS -DPOCO_ENABLE_CPP11 -DPOCO_ENABLE_CPP14 \
    -DPOCO_HAVE_FD_EPOLL -DPOCO_OS_FAMILY_UNIX \
    -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE \
    -D_REENTRANT -D_THREAD_SAFE -D_XOPEN_SOURCE=500 \
    -I/src/poco/JSON/include \
    -I/src/poco/Foundation/include \
    -O2 -g -DNDEBUG -std=gnu++14 \
    -o json_fuzzer.o -c $SRC/json_parse_fuzzer.cc

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE json_fuzzer.o \
    ./lib/libPocoJSON.a \
    ./lib/libPocoFoundation.a \
    -o $OUT/json_parser_fuzzer -lpthread -ldl -lrt

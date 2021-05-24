#!/bin/bash -eu
# Copyright 2020 LLC
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

cd build
cmake ../srcs -DBUILD_ONLY_STATIC_LIB=ON 
make -j$(nproc)


$CXX $CXXFLAGS -DHEIF_USE_STATIC_LIB \
  -c $SRC/heif_reader_fuzzer.cpp \
  -o heif_reader_fuzzer.o \
  -I/src/heif/build \
  -I/src/heif/srcs/api/common \
  -I/src/heif/srcs/api/reader \
  -I/src/heif/srcs/api/writer \
  -g -fPIE -std=c++11

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -rdynamic \
  heif_reader_fuzzer.o -o $OUT/reader_fuzzer \
  /src/heif/build/lib/libheif_static.a \
  /src/heif/build/lib/libheif_writer_static.a

#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# b44ExpLogTable.cpp only contains a definition of main().
sed -i 's/Source\/OpenEXR\/IlmImf\/b44ExpLogTable.cpp//' Makefile.srcs
sed -i 's/Source\/LibTIFF4\/tif_getimage.c/Source\/LibTIFF4\/tif_getimage.c Source\/LibTIFF4\/tif_hash_set.c/g' ./Makefile.srcs
export CXXFLAGS="$CXXFLAGS -std=c++14"  # Avoid C++17 build error
(
 # Avoid tmpnam link error
 cd Source/LibJXR
 dos2unix ./image/encode/strenc.c
 patch -p1 -i $SRC/jxrlib_tmpnam.patch
)
make LIBRARIES=-lc++ -j$(nproc) -f Makefile.gnu libfreeimage.a

INSTALL_DIR=$PWD

cd $SRC

$CXX $CXXFLAGS -I${INSTALL_DIR}/ -I${INSTALL_DIR}/Source $LIB_FUZZING_ENGINE \
  load_from_memory_fuzzer.cc ${INSTALL_DIR}/libfreeimage.a \
  -o $OUT/load_from_memory_fuzzer

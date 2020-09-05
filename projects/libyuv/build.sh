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
# First install libjpeg
cd libjpeg-turbo
mkdir build && cd build
cmake ..
make

# Set include flags and HAVE_JPEG option
export CFLAGS="$CFLAGS -I$PWD -I$PWD/.. -DHAVE_JPEG"
export CXXFLAGS="$CXXFLAGS -I$PWD -I$PWD/.. -DHAVE_JPEG"

# Install libyuv, make sure HAVE_JPEG is set
cd $SRC/libyuv
make libyuv.a -f linux.mk

# Compile the fuzzer
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -I./include -I./include/libyuv ./source/*.o \
    $SRC/fuzz_jpeg.cc $SRC/libjpeg-turbo/build/libjpeg.a -o $OUT/fuzz_jpeg_decoder

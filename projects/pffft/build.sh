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

SRC_DIR=$SRC/pffft
cd $WORK

# Building PFFFT as a static library.
if [ -f libpffft.a ]; then
  rm libpffft.a
fi
$CXX $CXXFLAGS -c -msse2 -fPIC $SRC_DIR/pffft.c -o pffft.o
ar rcs libpffft.a pffft.o

# Building PFFFT fuzzers.
$CXX $CXXFLAGS -std=c++11 -I$SRC_DIR \
     $SRC/pffft_fuzzer.cc -o $OUT/pffft_real_fwbw_fuzzer \
     -lFuzzingEngine $WORK/libpffft.a

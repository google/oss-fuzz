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

cd libiec61850
mkdir build && cd build
cmake ../
make

$CC $CFLAGS $LIB_FUZZING_ENGINE ../fuzz/fuzz_mms_decode.c -c \
	-I../src/iec61850/inc -I../src/mms/inc -I../src/common/inc \
	-I../hal/inc -I../src/logging


$CXX $CXXFLAGS -fuse-ld=lld $LIB_FUZZING_ENGINE fuzz_mms_decode.o -o $OUT/fuzz_mms_decode ./src/libiec61850.a ./hal/libhal.a

# Copy over the options file
cp $SRC/fuzz_decode.options $OUT/fuzz_decode.options

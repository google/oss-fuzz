#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

# build the library.
./autogen.sh
make -j$(nproc) clean
make -j$(nproc) all

# build your fuzzer(s)
$CC $CFLAGS -c $SRC/libtsm_fuzzer.c -Isrc/tsm -o $SRC/libtsm_fuzzer.o
$CXX $CXXFLAGS \
    -o $OUT/libtsm_fuzzer \
    $SRC/libtsm_fuzzer.o \
    .libs/libtsm.a \
    $LIB_FUZZING_ENGINE

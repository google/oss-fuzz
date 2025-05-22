#!/bin/bash -eu
# Copyright 2023 Google LLC
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

autoreconf -i
./configure --enable-shared=no --enable-static=yes
make
$CC $CFLAGS $LIB_FUZZING_ENGINE -I./include -c $SRC/fuzz_libunwind.c \
    -o fuzz_libunwind.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_libunwind.o \
    ./src/.libs/libunwind-x86_64.a ./src/.libs/libunwind.a \
    -o $OUT/fuzz_libunwind

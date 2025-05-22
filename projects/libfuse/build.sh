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

mkdir build
cd build
meson setup ..
meson configure -D default_library=static
ninja

$CC $CFLAGS -c $SRC/fuzz_optparse.c -o fuzz_optparse.o \
  -I$SRC/libfuse/lib/ -I$SRC/libfuse/include -I./ \
  -I$SRC/fuzz-headers/lang/c \
  -Wincompatible-pointer-types-discards-qualifiers

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_optparse.o \
  -o $OUT/fuzz_optparse lib/libfuse3.a 

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

#export CFLAGS="${CFLAGS} -"
#export CXXFLAGS="${CXXFLAGS} -ltinfo"

cd w3m
./configure

make myctype.o
make Str.o
make libwc

cd libwc
$CC $CFLAGS -c ../fuzz/fuzz-conv.c -o fuzz_conv.o -I../ -I./
static_libgc=($(find /usr/lib -name "libgc.a"))
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_conv.o -o $OUT/fuzz_conv \
    -I./libwc  -DUSE_UNICODE -I. -I./.. -DHAVE_CONFIG_H ../Str.o ../myctype.o libwc.a ${static_libgc}

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
cd lexbor
mkdir build && cd build
cmake .. 
make

$CC $CFLAGS -I/src/lexbor/source -Wall -pedantic -pipe -std=c99 -fPIC -c  /src/lexbor/test/fuzzers/lexbor/encoding/decode.c
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -stdlib=libc++ -Wall -pedantic -pipe -std=c99 -fPIC decode.o  /src/lexbor/build/liblexbor_static.a -Wl,-rpath,/src/lexbor/build -o $OUT/fuzz_decode

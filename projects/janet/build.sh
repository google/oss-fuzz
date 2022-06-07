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
export CFLAGS="$CFLAGS -fPIC"
cd janet
make

$CC -D_XOPEN_SOURCE=600 $CFLAGS -DJANET_BOOTSTRAP -Isrc/include -Isrc/conf -std=c99 -fPIC -o fuzz_dostring.o -c ./test/fuzzers/fuzz_dostring.c
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_dostring.o build/libjanet.a -o $OUT/fuzz_dostring

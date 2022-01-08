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

cd libredwg
sh ./autogen.sh
# enable-release to skip unstable preR13. bindings are not fuzzed.
./configure --disable-shared --disable-bindings --enable-release
make

$CC $CFLAGS $LIB_FUZZING_ENGINE examples/llvmfuzz.c -o $OUT/llvmfuzz \
    src/.libs/libredwg.a -I./include -I./src

cp $SRC/llvmfuzz.options $OUT/llvmfuzz.options

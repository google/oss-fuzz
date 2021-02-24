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
./configure --disable-shared
make

$CC $CFLAGS $LIB_FUZZING_ENGINE ./test/fuzz/fuzz_dwg_decode.c -o $OUT/fuzz_dwg_decode \
    src/.libs/libredwg.a -I./include -I./src


cp $SRC/fuzz_dwg_decode.options $OUT/fuzz_dwg_decode.options

#!/bin/bash -euo
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

rm -rf "${WORK:?}/"*
make clean

npm ci
yes | make build/libllhttp.a

$CC $CFLAGS -c ./test/fuzzers/fuzz_parser.c -I./build/ ./build/libllhttp.a -o $WORK/fuzz_parser.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -fuse-ld=lld -I./build/ ./build/libllhttp.a $WORK/fuzz_parser.o -o $OUT/fuzz_parser

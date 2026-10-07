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

./autogen.sh
./configure
make libnuma.la

$CC $CFLAGS -c ./fuzz/fuzz_parse_str.c -o fuzz_parse_str.o -I./

# Link with CXX as this is needed for OSS-Fuzz Centipede
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_parse_str.o ./.libs/libnuma.a -o $OUT/fuzz_parse_str

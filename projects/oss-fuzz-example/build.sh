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

# Build project using the OSS-Fuzz enviroonment flags.
$CC $CFLAGS -c char_lib.c -o char_lib.o

# Build the fuzzers. We must ensure we link with $CXX to support Centipede.
# Fuzzers must be placed in $OUT/
$CC $CFLAGS -c fuzz_char_lib.c -o fuzz_char_lib.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_char_lib.o char_lib.o -o $OUT/fuzz_char_lib

$CC $CFLAGS -c fuzz_complex_parser.c -o fuzz_complex_parser.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_complex_parser.o char_lib.o -o $OUT/fuzz_complex_parser

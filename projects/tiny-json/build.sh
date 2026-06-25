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

for fuzzer in $(find $SRC -name 'fuzz_*.c'); do
    fuzzer_name=$(basename $fuzzer .c)
    $CXX $CXXFLAGS $SRC/$fuzzer_name.c -c -o $fuzzer_name.o
    $CXX $CXXFLAGS $SRC/tiny-json/tiny-json.c -c -o tiny-json.o
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer_name.o tiny-json.o -o $OUT/$fuzzer_name
done


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

make USE_SSL=0 static
mv fuzzing/format_command_fuzzer.c .

$CC $CFLAGS -std=c99 -pedantic -c -O3 -fPIC \
	format_command_fuzzer.c -o format_command_fuzzer.o

$CXX $CXXFLAGS -O3 -fPIC $LIB_FUZZING_ENGINE format_command_fuzzer.o \
	-o $OUT/format_command_fuzzer libhiredis.a

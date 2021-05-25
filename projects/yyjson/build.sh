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

mkdir build-dir && cd build-dir
cmake ..
make -j$(nproc)

$CC $CFLAGS -I/src/yyjson/src \
	-c $SRC/read_fuzzer.cc \
	-o read_fuzzer.o
$CC $CFLAGS $LIB_FUZZING_ENGINE \
	read_fuzzer.o -o $OUT/read_fuzzer \
    ./CMakeFiles/yyjson.dir/src/yyjson.c.o

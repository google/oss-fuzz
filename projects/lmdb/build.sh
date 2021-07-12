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

cd libraries/liblmdb
sed -i '26 s/CFLAGS	=/CFLAGS	+=/' ./Makefile
sed -i '21d' ./Makefile

make -j$(nproc)
$CC $CXXFLAGS -I. -c $SRC/lmdb_fuzzer.c -o lmdb_fuzzer.o
$CC $CXXFLAGS $LIB_FUZZING_ENGINE lmdb_fuzzer.o \
    $(find $SRC -name liblmdb.a) -o $OUT/lmdb_fuzzer

#!/bin/bash -eu
# Copyright 2025 Google LLC
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

SRC_DIR="$SRC/zxc_project"

$CC $CFLAGS -I"$SRC_DIR/include" -I"$SRC_DIR/src/lib" -c "$SRC_DIR/src/lib/zxc_common.c" -o zxc_common.o
$CC $CFLAGS -I"$SRC_DIR/include" -I"$SRC_DIR/src/lib" -c "$SRC_DIR/src/lib/zxc_compress.c" -o zxc_compress.o
$CC $CFLAGS -I"$SRC_DIR/include" -I"$SRC_DIR/src/lib" -c "$SRC_DIR/src/lib/zxc_decompress.c" -o zxc_decompress.o

ar rcs libzxc.a zxc_common.o zxc_compress.o zxc_decompress.o

$CC $CFLAGS -I$SRC_DIR/include -c $SRC_DIR/tests/fuzz.c -o fuzz.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz.o libzxc.a \
    -o "$OUT/zxc_fuzzer" \
    -lpthread -lm

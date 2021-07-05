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

mkdir build
cd build
cmake ..
make -j$(nproc)

$CC $CFLAGS -DH3_PREFIX="" \
    -I/src/h3/src/apps/applib/include \
    -I/src/h3/src/h3lib/include \
    -I/src/h3/build/src/h3lib/include \
    -o h3_fuzzer.o \
    -c $SRC/h3_fuzzer.c

$CC $CFLAGS $LIB_FUZZING_ENGINE -rdynamic \
    h3_fuzzer.o \
    -o $OUT/h3_fuzzer \
    lib/libh3.a


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
cd libyang
mkdir build && cd build
cmake ../ -DENABLE_STATIC=ON 
make

# Fuzz
cp $SRC/fuzz_yang.c .
$CC $CFLAGS $LIB_FUZZING_ENGINE fuzz_yang.c -o $OUT/fuzz_yan \
    libyang.a libyangdata.a libuser_inet_types.a libmetadata.a \
    libuser_yang_types.a libnacm.a -I./src -I../src -lpcre

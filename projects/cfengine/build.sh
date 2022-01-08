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

./autogen.sh
./configure
make V=1 -j$(nproc)

cd libpromises
mv $SRC/string_fuzzer.c .
find . -name "*.o" -exec ar rcs fuzz_lib.a {} \;
$CC $CFLAGS -I./ -c string_fuzzer.c -o string_fuzzer.o
$CC $CXXFLAGS $LIB_FUZZING_ENGINE string_fuzzer.o \
    -o $OUT/string_fuzzer fuzz_lib.a \
    ../libntech/libutils/.libs/libutils.a

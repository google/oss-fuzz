#!/bin/bash -eu
#
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
./configure --enable-static --disable-shared LDFLAGS="-static" CFLAGS="${CFLAGS}" LDFLAGS="${CFLAGS}"
make LDFLAGS=-all-static

for f in $SRC/*_fuzzer.c; do
  fuzzer=$(basename "$f" _fuzzer.c)
  $CC $CFLAGS -I$SRC/hwloc/include -c $SRC/${fuzzer}_fuzzer.c \
    -o $SRC/${fuzzer}_fuzzer.o
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $SRC/${fuzzer}_fuzzer.o \
    -o $OUT/${fuzzer}_fuzzer \
    -Wl,--start-group ./hwloc/.libs/libhwloc.a ./netloc/.libs/libnetloc.a \
    ./utils/hwloc/.libs/libutils_common.a -Wl,--end-group
done

cp $SRC/*.options $OUT/

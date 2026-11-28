#!/bin/bash -eu
# Copyright 2026 Google LLC
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

# Build libnl as a static library
cd $SRC/libnl
autoreconf -fiv
./configure --enable-static --disable-shared
make -j$(nproc)

LIBNL=$SRC/libnl
INCLUDES="-I$LIBNL/include"
CORE_LIB="$LIBNL/lib/.libs/libnl-3.a"
ROUTE_LIB="$LIBNL/lib/.libs/libnl-route-3.a"
NF_LIB="$LIBNL/lib/.libs/libnl-nf-3.a"
IDIAG_LIB="$LIBNL/lib/.libs/libnl-idiag-3.a"

# fuzz_msg, fuzz_attr, fuzz_addr only need the core library
for fuzzer in fuzz_msg fuzz_attr fuzz_addr; do
    $CC $CFLAGS $INCLUDES -c $SRC/$fuzzer.c -o $fuzzer.o
    $CXX $CXXFLAGS $fuzzer.o -o $OUT/$fuzzer $LIB_FUZZING_ENGINE $CORE_LIB
done

# fuzz_route and fuzz_neigh need libnl-route
for fuzzer in fuzz_route fuzz_neigh; do
    $CC $CFLAGS $INCLUDES -c $SRC/$fuzzer.c -o $fuzzer.o
    $CXX $CXXFLAGS $fuzzer.o -o $OUT/$fuzzer $LIB_FUZZING_ENGINE \
        $ROUTE_LIB $CORE_LIB
done

# fuzz_ct needs libnl-nf
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_ct.c -o fuzz_ct.o
$CXX $CXXFLAGS fuzz_ct.o -o $OUT/fuzz_ct $LIB_FUZZING_ENGINE \
    $NF_LIB $CORE_LIB

# fuzz_idiag needs libnl-idiag
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_idiag.c -o fuzz_idiag.o
$CXX $CXXFLAGS fuzz_idiag.o -o $OUT/fuzz_idiag $LIB_FUZZING_ENGINE \
    $IDIAG_LIB $CORE_LIB

#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# build projects
#mbedtls
cd mbedtls
cmake . -DENABLE_PROGRAMS=0 -DENABLE_TESTING=0
make -j$(nproc) all

#libecc
cd ../libecc
#required by libecc
export ORIGCFLAGS=$CFLAGS
export CFLAGS="$CFLAGS -fPIC"
make
export CFLAGS=$ORIGCFLAGS

#build fuzz target
cd ../ecfuzzer
$CC $CFLAGS -I. -c fuzz_ec.c -o fuzz_ec.o
$CC $CFLAGS -I. -I../mbedtls/include -c mbedtls.c -o mbedtls.o
export CFLAGS="$CFLAGS -DWITH_STDLIB"
$CC $CFLAGS -I. -I../libecc/src -c libecc.c -o libecc.o
export CFLAGS=$ORIGCFLAGS

$CXX $CXXFLAGS fuzz_ec.o mbedtls.o libecc.o -o $OUT/fuzz_ec ../mbedtls/library/libmbedcrypto.a ../libecc/build/libec.a -lFuzzingEngine

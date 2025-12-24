#!/bin/bash -eux
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

# Build the project to ensure headers are generated if needed
./configure --enable-static --disable-shared
make -j$(nproc)

# Build the cJSON fuzzer
# We link against src/cjson.c directly as it is a standalone file in the source
$CC $CFLAGS -Isrc -c $SRC/cjson_fuzzer.c -o cjson_fuzzer.o
$CC $CFLAGS -Isrc -c src/cjson.c -o cjson.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE cjson_fuzzer.o cjson.o -lm -o $OUT/cjson_fuzzer

# Build the auth fuzzer
$CC $CFLAGS -Isrc -DHAVE_SSL -c $SRC/auth_fuzzer.c -o auth_fuzzer.o
$CC $CFLAGS -Isrc -DHAVE_SSL -c src/iperf_auth.c -o iperf_auth.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE auth_fuzzer.o iperf_auth.o -lssl -lcrypto -o $OUT/auth_fuzzer

# Build the api fuzzer
$CC $CFLAGS -Isrc -c $SRC/iperf_api_fuzzer.c -o iperf_api_fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE iperf_api_fuzzer.o src/.libs/libiperf.a -lssl -lcrypto -Wl,--wrap=iperf_errexit -Wl,--wrap=iperf_exit -Wl,--wrap=exit -Wl,--wrap=abort -o $OUT/iperf_api_fuzzer

# Build the server fuzzer
$CC $CFLAGS -Isrc -c $SRC/iperf_server_fuzzer.c -o iperf_server_fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE iperf_server_fuzzer.o src/.libs/libiperf.a -lssl -lcrypto -Wl,--wrap=iperf_errexit -Wl,--wrap=iperf_exit -Wl,--wrap=exit -Wl,--wrap=abort -o $OUT/iperf_server_fuzzer




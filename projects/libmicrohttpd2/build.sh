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

# Avoid memory leak
export ASAN_OPTIONS=detect_leaks=0
export LSAN_OPTIONS=detect_leaks=0

# Build libmicrohttpd
./autogen.sh
./configure --enable-dauth --enable-md5 --enable-sha256 --enable-sha512-256 \
  --enable-bauth --enable-upgrade --enable-https --enable-messages --enable-coverage
make clean
make -j$(nproc)
BINARY=$SRC/mhd2/src/mhd2/.libs/libmicrohttpd2.a

# Compile fuzzer
clang++ $CXXFLAGS $SRC/fuzz_mhd2.cpp \
    -fprofile-instr-generate -Wno-unused-parameter -Wno-unused-value \
    -fcoverage-mapping -pthread -I$SRC -I$SRC/mhd2/src \
    -I$SRC/mhd2/src/include -I./ -fsanitize=fuzzer $BINARY -lgnutls \
    -o $OUT/fuzz_mhd2

clang++ $CXXFLAGS $SRC/fuzz_response.cpp $SRC/mhd_helper.cpp \
    -fprofile-instr-generate -Wno-unused-parameter -Wno-unused-value \
    -fcoverage-mapping -pthread -I$SRC -I$SRC/mhd2/src \
    -I$SRC/mhd2/src/include -I./ -fsanitize=fuzzer $BINARY -lgnutls \
    -o $OUT/fuzz_response

clang++ $CXXFLAGS $SRC/fuzz_daemon.cpp $SRC/mhd_helper.cpp \
    -fprofile-instr-generate -Wno-unused-parameter -Wno-unused-value \
    -fcoverage-mapping -pthread -I$SRC -I$SRC/mhd2/src \
    -I$SRC/mhd2/src/include -I./ -fsanitize=fuzzer $BINARY -lgnutls \
    -o $OUT/fuzz_daemon

#!/bin/bash -eu
# Copyright 2020 Google Inc.
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
cd librdkafka
mkdir build
cd build
cmake -DRDKAFKA_BUILD_STATIC=ON -DRDKAFKA_BUILD_EXAMPLES=OFF -DHAVE_REGEX=OFF ../
make

$CC -g -fPIC $CFLAGS -I$SRC/librdkafka/src -Igenerated/dummy \
    -c $SRC/librdkafka/tests/fuzzers/fuzz_regex.c -o fuzz_regex.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -rdynamic fuzz_regex.o -o fuzzer \
    ./src-cpp/librdkafka++.a ./src/librdkafka.a -lm -lssl -lcrypto \
    -lcrypto -lz -ldl -lpthread -lrt
cp fuzzer $OUT/fuzz_regex

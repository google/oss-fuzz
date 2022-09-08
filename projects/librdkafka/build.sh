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
./configure --install-deps --disable-regex-ext
make

export LIBZSTD=$PWD/mklove/deps/dest/usr/lib/libzstd.a

cd tests
$CC -g -fPIC $CFLAGS -I../src -c ./fuzzers/fuzz_regex.c -o fuzz_regex.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -rdynamic fuzz_regex.o -o fuzzer \
    ../src/librdkafka.a -lm ${LIBZSTD} -lsasl2 -lssl -lcrypto \
    -lcrypto -lz -ldl -lpthread -lrt

cp fuzzer $OUT/fuzz_regex

#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

# Build the project.
./buildconf
./configure --enable-debug --disable-tests
make clean
make -j$(nproc) V=1 all

# Build the fuzzers.
$CC $CFLAGS -Iinclude -Isrc/lib -c $SRC/c-ares/test/ares-test-fuzz.c -o $WORK/ares-test-fuzz.o
$CXX $CXXFLAGS -std=c++11 $WORK/ares-test-fuzz.o \
    -o $OUT/ares_parse_reply_fuzzer \
    $LIB_FUZZING_ENGINE $SRC/c-ares/src/lib/.libs/libcares.a

$CC $CFLAGS -Iinclude -Isrc/lib -c $SRC/c-ares/test/ares-test-fuzz-name.c \
    -o $WORK/ares-test-fuzz-name.o
$CXX $CXXFLAGS -std=c++11 $WORK/ares-test-fuzz-name.o \
    -o $OUT/ares_create_query_fuzzer \
    $LIB_FUZZING_ENGINE $SRC/c-ares/src/lib/.libs/libcares.a

# Archive and copy to $OUT seed corpus if the build succeeded.
zip -j $OUT/ares_parse_reply_fuzzer_seed_corpus.zip $SRC/c-ares/test/fuzzinput/*
zip -j $OUT/ares_create_query_fuzzer_seed_corpus.zip \
    $SRC/c-ares/test/fuzznames/*

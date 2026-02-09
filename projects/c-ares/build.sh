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

cd $SRC/googletest
mkdir build
cd build
cmake ..
make -j$(nproc)
make install

cd $SRC/c-ares

# Build the project.
./buildconf
./configure --enable-debug --enable-tests
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

# Build the new coverage-improvement fuzzers.
$CC $CFLAGS -Iinclude -Isrc/lib -c $SRC/fuzz_ares_name.c -o $WORK/fuzz_ares_name.o
$CXX $CXXFLAGS -std=c++11 $WORK/fuzz_ares_name.o \
    -o $OUT/fuzz_ares_name \
    $LIB_FUZZING_ENGINE $SRC/c-ares/src/lib/.libs/libcares.a

$CC $CFLAGS -Iinclude -Isrc/lib -c $SRC/fuzz_ares_config.c -o $WORK/fuzz_ares_config.o
$CXX $CXXFLAGS -std=c++11 $WORK/fuzz_ares_config.o \
    -o $OUT/fuzz_ares_config \
    $LIB_FUZZING_ENGINE $SRC/c-ares/src/lib/.libs/libcares.a

$CC $CFLAGS -Iinclude -Isrc/lib -c $SRC/fuzz_ares_record.c -o $WORK/fuzz_ares_record.o
$CXX $CXXFLAGS -std=c++11 $WORK/fuzz_ares_record.o \
    -o $OUT/fuzz_ares_record \
    $LIB_FUZZING_ENGINE $SRC/c-ares/src/lib/.libs/libcares.a

# Copy dictionaries.
cp $SRC/fuzz_ares_name.dict $OUT/fuzz_ares_name.dict
cp $SRC/fuzz_ares_config.dict $OUT/fuzz_ares_config.dict
cp $SRC/fuzz_ares_record.dict $OUT/fuzz_ares_record.dict

# Archive and copy to $OUT seed corpus if the build succeeded.
zip -j $OUT/ares_parse_reply_fuzzer_seed_corpus.zip $SRC/c-ares/test/fuzzinput/*
zip -j $OUT/ares_create_query_fuzzer_seed_corpus.zip \
    $SRC/c-ares/test/fuzznames/*

# Create seed corpora for the new fuzzers.
# fuzz_ares_name seeds: use existing DNS inputs plus name-focused seeds
mkdir -p $WORK/name_seeds
cp $SRC/c-ares/test/fuzzinput/* $WORK/name_seeds/ 2>/dev/null || true
cp $SRC/c-ares/test/fuzznames/* $WORK/name_seeds/ 2>/dev/null || true
zip -j $OUT/fuzz_ares_name_seed_corpus.zip $WORK/name_seeds/*

# fuzz_ares_config seeds: create some basic config strings
mkdir -p $WORK/config_seeds
echo -ne '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > $WORK/config_seeds/basic_opts
echo -ne '\x01127.0.0.1:53,8.8.8.8:53' > $WORK/config_seeds/servers_csv
echo -ne '\x01192.168.0.0/16 10.0.0.0/8' > $WORK/config_seeds/sortlist
echo -ne '\x03\x7f\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01eth0' > $WORK/config_seeds/local_ip
zip -j $OUT/fuzz_ares_config_seed_corpus.zip $WORK/config_seeds/*

# fuzz_ares_record seeds: create some basic DNS record construction seeds
mkdir -p $WORK/record_seeds
echo -ne '\x00\x00\x01\x00\x00\x00\x00\x00\x07example\x03com\x00' > $WORK/record_seeds/query_a
echo -ne '\x00\x00\x01\x00\x00\x01\x00\x01\x07example\x03com\x00' > $WORK/record_seeds/query_aaaa
echo -ne '\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04test\x03com\x00' > $WORK/record_seeds/response
echo -ne '\x02\x00127.0.0.1' > $WORK/record_seeds/pton_v4
echo -ne '\x02\x01::1' > $WORK/record_seeds/pton_v6
echo -ne '\x03\x01\x00\x02\x00\x03\x00\x04\x00' > $WORK/record_seeds/enums
zip -j $OUT/fuzz_ares_record_seed_corpus.zip $WORK/record_seeds/*

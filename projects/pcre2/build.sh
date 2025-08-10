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

# build project
./autogen.sh
./configure --enable-fuzz-support \
    --enable-never-backslash-C --with-match-limit=1000000 --with-match-limit-depth=1000000 \
    --enable-jit \
    --enable-pcre2-16 --enable-pcre2-32
make -j$(nproc) clean
make -j$(nproc) all

# build fuzzers
$CXX $CXXFLAGS -o $OUT/pcre2_fuzzer \
    $LIB_FUZZING_ENGINE .libs/libpcre2-fuzzsupport.a .libs/libpcre2-8.a
$CXX $CXXFLAGS -o $OUT/pcre2_fuzzer_16 \
    $LIB_FUZZING_ENGINE .libs/libpcre2-fuzzsupport-16.a .libs/libpcre2-16.a
$CXX $CXXFLAGS -o $OUT/pcre2_fuzzer_32 \
    $LIB_FUZZING_ENGINE .libs/libpcre2-fuzzsupport-32.a .libs/libpcre2-32.a

# test different link sizes
for i in $(seq 3 4); do
    ./configure --enable-fuzz-support \
        --enable-never-backslash-C --with-match-limit=1000000 --with-match-limit-depth=1000000 \
        --enable-jit \
        --enable-pcre2-16 --enable-pcre2-32 --with-link-size=${i}
    make -j$(nproc) clean
    make -j$(nproc) all

    # build fuzzers
    $CXX $CXXFLAGS -o $OUT/pcre2_fuzzer_${i}l \
        $LIB_FUZZING_ENGINE .libs/libpcre2-fuzzsupport.a .libs/libpcre2-8.a
    $CXX $CXXFLAGS -o $OUT/pcre2_fuzzer_16_${i}l \
        $LIB_FUZZING_ENGINE .libs/libpcre2-fuzzsupport-16.a .libs/libpcre2-16.a
    $CXX $CXXFLAGS -o $OUT/pcre2_fuzzer_32_${i}l \
        $LIB_FUZZING_ENGINE .libs/libpcre2-fuzzsupport-32.a .libs/libpcre2-32.a
done

# set up dictionary and options to use it
for bits in "" "_16" "_32"; do
  cp "testdata/fuzzing/pcre2_fuzzer${bits}.dict" "${OUT}/pcre2_fuzzer${bits}.dict"
  for linksize in "" "_3l" "_4l"; do
    cp "testdata/fuzzing/pcre2_fuzzer${bits}.options" "${OUT}/pcre2_fuzzer${bits}${linksize}.options"
  done
done

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

# build project
cd $SRC
tar xzf lzo.tar.gz
cd lzo-*
./configure && make -j$(nproc)

# build fuzzers
for file in $SRC/*.c;
do
    name=$(basename $file .c)
    $CC $CFLAGS -c -I include -I minilzo -I include/lzo ${file} -o ${name}.o
    $CXX $CXXFLAGS -std=c++11 -I include -I minilzo -I include/lzo ${name}.o \
        -o $OUT/${name} $LIB_FUZZING_ENGINE src/.libs/liblzo2.a
done

$CXX $CXXFLAGS -std=c++11 -I include -I minilzo -I include/lzo \
    $SRC/all_lzo_compress.cc \
    -o $OUT/all_lzo_compress $LIB_FUZZING_ENGINE src/.libs/liblzo2.a

# copy fuzzer options
cp $SRC/*.options $OUT/
zip -j $OUT/lzo_decompress_target_seed_corpus.zip $SRC/lzo_decompress_target_seeds/*

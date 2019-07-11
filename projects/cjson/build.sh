#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

mkdir build
cd build
cmake -DBUILD_SHARED_LIBS=OFF -DENABLE_CJSON_TEST=OFF ..
make -j5

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/cjson/fuzzing/cjson_read_fuzzer.cc \
    -o $OUT/cjson_read_fuzzer \
    $LIB_FUZZING_ENGINE $SRC/cjson/build/libcjson.a

find $SRC/cjson/fuzzing/inputs -name "*" | \
     xargs zip $OUT/cjson_read_fuzzer_seed_corpus.zip

cp $SRC/cjson/fuzzing/json.dict $SRC/cjson/fuzzing/cjson_read_fuzzer.dict
cp $SRC/cjson/fuzzing/cjson_read_fuzzer.dict $OUT/

#!/bin/bash -eu
# Copyright 2024 Google LLC
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

./bootstrap.sh

echo "using clang : ossfuzz : $CXX : <compileflags>\"$CXXFLAGS\" <linkflags>\"$CXXFLAGS\" <linkflags>\"${LIB_FUZZING_ENGINE}\" ;" >user-config.jam

./b2 --user-config=user-config.jam --toolset=clang-ossfuzz --prefix=$WORK/stage --with-headers link=static install

tar -xvf libs/beast/test/fuzz/seeds.tar -C libs/beast/test/fuzz

for i in libs/beast/test/fuzz/*.cpp; do
    fuzzer=$(basename $i .cpp)
    $CXX $CXXFLAGS -pthread -I $WORK/stage/include libs/beast/test/fuzz/$fuzzer.cpp $LIB_FUZZING_ENGINE -o $OUT/$fuzzer

    if [ -d "libs/beast/test/fuzz/seeds/$fuzzer" ]; then
        zip -q -r -j $OUT/"$fuzzer"_seed_corpus.zip libs/beast/test/fuzz/seeds/$fuzzer
    fi
done

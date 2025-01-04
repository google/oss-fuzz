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

mkdir build
cd build

cmake -DCMAKE_BUILD_TYPE=Release ..
make -j4

cp $SRC/yaml-cpp-fuzzer/*.dict $OUT/
cp $SRC/yaml-cpp-fuzzer/*.options $OUT/

for fuzzer in $(find $SRC/yaml-cpp-fuzzer/ -name "*_fuzzer.cpp"); do
    fuzzer_basename=$(basename -s .cpp $fuzzer)
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        -I$SRC/yaml-cpp/include \
        $fuzzer \
        -o $OUT/$fuzzer_basename \
        libyaml-cpp.a

    zip -q $OUT/${fuzzer_basename}_seed_corpus.zip $SRC/yaml-cpp-fuzzer/${fuzzer_basename}_seed_corpus/*
done


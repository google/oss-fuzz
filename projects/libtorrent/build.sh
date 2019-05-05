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

export PATH=${PATH}:${PWD}/../boost_1_69_0/tools/build/src/engine/bin.linuxx86_64
export BOOST_ROOT=${PWD}/../boost_1_69_0
export BOOST_BUILD_PATH=${PWD}/../boost_1_69_0/tools/build

(cd ${PWD}/../boost_1_69_0 && ./bootstrap.sh)

echo "CXX=$CXX"
echo "CXXFLAGS=$CXXFLAGS"

echo "using clang : ossfuzz : $CXX : <compileflags>\"$CXXFLAGS\" <linkflags>\"$CXXFLAGS\" <linkflags>\"${LIB_FUZZING_ENGINE}\" ;" >project-config.jam
cat project-config.jam
cd fuzzers
b2 clang-ossfuzz -j$(nproc) crypto=openssl fuzz=external sanitize=off stage-large
cp fuzzers/* $OUT

wget --no-verbose https://github.com/arvidn/libtorrent/releases/download/libtorrent-1_2_1/corpus.zip
unzip -q corpus.zip
cd corpus
for f in *; do
zip -q -r ${OUT}/fuzzer_${f}_seed_corpus.zip ${f}
done

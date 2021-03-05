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

export PATH=${PATH}:${PWD}/../boost
export BOOST_ROOT=${PWD}/../boost
export BOOST_BUILD_PATH=${PWD}/../boost/tools/build
# when building b2, we don't want sanitizers enabled
ASAN_OPTIONS=detect_leaks=0
(cd ${PWD}/../boost && ./bootstrap.sh && ./b2 headers)

echo "CXX=$CXX"
echo "CXXFLAGS=$CXXFLAGS"

echo "using clang : ossfuzz : $CXX : <compileflags>\"$CXXFLAGS\" <linkflags>\"$CXXFLAGS\" <linkflags>\"${LIB_FUZZING_ENGINE}\" ;" >project-config.jam
cat project-config.jam
cd fuzzers
# we don't want sanitizers enabled on b2 itself
ASAN_OPTIONS=detect_leaks=0 b2 clang-ossfuzz -j$(nproc) crypto=openssl fuzz=external sanitize=off stage-large logging=off
cp fuzzers/* $OUT

wget --no-verbose https://github.com/arvidn/libtorrent/releases/download/2.0/corpus.zip
unzip -q corpus.zip
cd corpus
for f in *; do
zip -q -r ${OUT}/fuzzer_${f}_seed_corpus.zip ${f}
done

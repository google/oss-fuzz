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
# e.g.
# ./autogen.sh
# ./configure
# make -j$(nproc) all

# build fuzzers
# e.g.
# $CXX $CXXFLAGS -std=c++11 -Iinclude \
#     /path/to/name_of_fuzzer.cc -o $OUT/name_of_fuzzer \
#     -lFuzzingEngine /path/to/library.a

# Download cmake binaries becaue the cmake version that is installed using
# `apt-get install cmake` is older than the minimum requirements.
cd $WORK
wget https://cmake.org/files/v3.12/cmake-3.12.0-Linux-x86_64.tar.gz
tar -xzf cmake-3.12.0-Linux-x86_64.tar.gz
export PATH=$PATH:$WORK/cmake-3.12.0-Linux-x86_64/bin
cd $SRC/firebase-ios-sdk
rm -rf build && mkdir build
cd build
echo "Work = ${WORK}"
ls $WORK
$WORK/cmake-3.12.0-Linux-x86_64/bin/cmake -DWITH_ASAN=ON -DFUZZING=ON -DOSS_FUZZ=ON -DOSS_FUZZING_ENGINE=${LIB_FUZZING_ENGINE} ..
make -j$(nproc)
cp Firestore/core/src/firebase/firestore/fuzzing/firebase_firestore_fuzzing_serializer $OUT/

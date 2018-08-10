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

# The cmake version that is available on Ubuntu 16.04 is 3.5.1. While Firestore
# itself requires cmake 3.5, it depends on leveldb which requires cmake 3.9
# (https://github.com/google/leveldb/blob/master/CMakeLists.txt#L5).
# There is an open issue (https://github.com/google/leveldb/issues/607) to
# lower the required cmake version of leveldb. Therefore, we need to download
# a newer version of cmake until leveldb lowers the required version or a newer
# cmake version becomes available in the OSS Fuzz environment.
cd $WORK
wget https://cmake.org/files/v3.12/cmake-3.12.0-Linux-x86_64.tar.gz
tar -xzf cmake-3.12.0-Linux-x86_64.tar.gz
rm cmake-3.12.0-Linux-x86_64.tar.gz

# Disable UBSan vptr since Firestore depends on other libraries that are built
# with -fno-rtti.
export CFLAGS="$CFLAGS -fno-sanitize=vptr"
export CXXFLAGS="$CXXFLAGS -fno-sanitize=vptr"

# Build the project using cmake with FUZZING option enabled to link to OSS Fuzz
# fuzzing library defined in ${LIB_FUZZING_ENGINE}.
cd $SRC/firebase-ios-sdk
mkdir build && cd build
$WORK/cmake-3.12.0-Linux-x86_64/bin/cmake -DFUZZING=ON ..
make -j$(nproc)

# Copy fuzzing targets, dictionaries, and zipped corpora to $OUT.
FUZZERS_DIR=Firestore/fuzzing
find ${FUZZERS_DIR} -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
find ${FUZZERS_DIR} -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
find ${FUZZERS_DIR} -name "*_fuzzer_seed_corpus" -type d -execdir zip -r ${OUT}/{}.zip {} ';'

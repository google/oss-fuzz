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

# Download binaries for cmake 3.12 because the cmake version that is installed
# using `apt-get install cmake` is older than the minimum cmake requirements.
cd $WORK
wget https://cmake.org/files/v3.12/cmake-3.12.0-Linux-x86_64.tar.gz
tar -xzf cmake-3.12.0-Linux-x86_64.tar.gz
rm cmake-3.12.0-Linux-x86_64.tar.gz

# Build the project using cmake with FUZZING option enabled.
cd $SRC/firebase-ios-sdk
mkdir build && cd build
$WORK/cmake-3.12.0-Linux-x86_64/bin/cmake -DFUZZING=ON ..
make -j$(nproc)

# Copy fuzzing targets and their dictionaries to $OUT.
FUZZERS_DIR=Firestore/core/src/firebase/firestore/fuzzing
find ${FUZZERS_DIR} -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
find ${FUZZERS_DIR} -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
# Zip corpora folders to $OUT.
find ${FUZZERS_DIR} -name "*_fuzzer_seed_corpus" -type d -execdir zip -r ${OUT}/{}.zip {} ';'

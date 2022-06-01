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

cd $WORK

# Disable UBSan vptr since Firestore depends on other libraries that are built
# with -fno-rtti.
export CFLAGS="$CFLAGS -fno-sanitize=vptr"
export CXXFLAGS="$CXXFLAGS -fno-sanitize=vptr"

# Build the project using cmake with FUZZING option enabled to link to OSS Fuzz
# fuzzing library defined in ${LIB_FUZZING_ENGINE}.
cd $SRC/firebase-ios-sdk

# Do not use Werror anywhere
sed -i 's/-Werror=reorder//g' ./cmake/compiler_setup.cmake
sed -i 's/-Werror=return-type//g' ./cmake/compiler_setup.cmake
sed -i 's/-Wall -Wextra -Werror//g' ./cmake/compiler_setup.cmake
sed -i 's/-Wuninitialized/#-Wu/g' ./cmake/compiler_setup.cmake
sed -i 's/-Wfno-common/#-Wu/g' ./cmake/compiler_setup.cmake
sed -i 's/-Werror//g' ./scripts/sync_project.rb
sed -i 's/-Werror=reorder//g' ./FirebaseFirestore.podspec
sed -i 's/ReadContext context/\/\/ReadContext/g' ./Firestore/fuzzing/serializer_fuzzer.cc
sed -i 's/serializer.Dec/\/\/serializer/g' ./Firestore/fuzzing/serializer_fuzzer.cc

mkdir build && cd build
cmake -DFIREBASE_IOS_BUILD_TESTS=OFF -DFIREBASE_IOS_BUILD_BENCHMARKS=OFF -DFUZZING=ON ..
make -j$(nproc)

# Copy fuzzing targets, dictionaries, and zipped corpora to $OUT.
FUZZERS_DIR=Firestore/fuzzing
find ${FUZZERS_DIR} -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
find ${FUZZERS_DIR} -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
find ${FUZZERS_DIR} -name "*_fuzzer_seed_corpus" -type d -execdir zip -r ${OUT}/{}.zip {} ';'

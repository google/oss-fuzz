#!/bin/bash -eu
# Copyright 2026 Google LLC
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

# Build the fuzz targets
git clone --branch issue/fix-oss-fuzz-build https://github.com/sandflow/OpenJPH.git
mkdir $SRC/build/
cd $SRC/build/
cmake $SRC/OpenJPH -DBUILD_SHARED_LIBS=OFF -DOJPH_BUILD_FUZZER=ON -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DCMAKE_C_FLAGS="$CFLAGS"
make -j$(nproc)
cp fuzzing/ojph_expand_fuzz_target $OUT

# Initialize the seed corpus
cd $SRC
git clone --depth 1 https://github.com/aous72/jp2k_test_codestreams.git
rm -f $OUT/ojph_expand_fuzz_target_seed_corpus.zip
zip -j $OUT/ojph_expand_fuzz_target_seed_corpus.zip jp2k_test_codestreams/openjph/*.j2c

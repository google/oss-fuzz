#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# Build fuzzer only
cd $SRC/flatbuffers
mkdir build
cd build
cmake -DOSS_FUZZ:BOOL=ON -G "Unix Makefiles" ../tests/fuzzer
make

cp ../tests/fuzzer/*.dict $OUT/
cp *.bfbs $OUT/
cp *_fuzzer $OUT/

# Build unit test
mkdir $SRC/flatbuffers/build-tests
cd $SRC/flatbuffers/build-tests
cmake -DFLATBUFFERS_BUILD_FLATC=ON -DFLATBUFFERS_BUILD_TESTS=ON ..
make flattests -j$(nproc)

#!/bin/bash -eu
# Copyright 2021 Google LLC
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
mkdir build
cd build
cmake .. \
  -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCATCH_DEVELOPMENT_BUILD=On \
  -DCATCH_BUILD_EXAMPLES=Off \
  -DCATCH_BUILD_EXTRA_TESTS=Off \
  -DCATCH_BUILD_TESTING=Off \
  -DBUILD_TESTING=Off \
  -DCATCH_ENABLE_WERROR=Off \
  -DCATCH_BUILD_FUZZERS=On

cmake --build . -j $(nproc)
cp fuzzing/fuzz* $OUT/

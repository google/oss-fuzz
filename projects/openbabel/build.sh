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

export CXXFLAGS="${CXXFLAGS} -std=c++17"
sed -i 's/CMAKE_CXX_STANDARD 11/CMAKE_CXX_STANDARD 17/g' CMakeLists.txt

# Remove use of deprecated functions
sed -i 's/std::random/\/\/std::random/g' test/*.cpp

# build project
mkdir build && cd build
cmake .. -DBUILD_SHARED=OFF -DBUILD_MIXED=ON
make -j $(nproc)
cp bin/fuzz* $OUT/

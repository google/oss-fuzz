#!/bin/bash -eu
# Copyright 2024 Google LLC
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

(
export CXXFLAGS="$CXXFLAGS -std=c++17"
export LDFLAGS="-stdlib=libc++"
# for UBSAN
export CFLAGS="$CFLAGS -fno-sanitize=function,vptr"
export CXXFLAGS="$CXXFLAGS -fno-sanitize=function,vptr"
cd $SRC/libdaq
./bootstrap
./configure --enable-static --disable-shared
make -j $(nproc) install
)

export CXXFLAGS="$CXXFLAGS -std=c++11"
# build project
./configure_cmake.sh
cd build
cmake -DBUILD_SHARED_LIBS=OFF ..
make -j $(nproc) fuzz
find . -name "*fuzz" | while read i; do cp $i $OUT/; done

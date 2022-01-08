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

# TODO(metzman): Use some kind of bash loop here.
mkdir glslang/build
pushd glslang/build

cmake -G "Ninja" -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_C_COMPILER=$CC -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" ..
ninja
cp StandAlone/glslangValidator $OUT
popd

mkdir SPIRV-Tools/build
pushd SPIRV-Tools/build

# TODO: If cmake respects LDFLAGS, do we need to specify the compilers and their flags?
# Link failure without LDFLAGS="-lpthread"
LDFLAGS="-lpthread" cmake -G "Ninja" -DSPIRV_SKIP_TESTS=ON  -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_C_COMPILER=$CC -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" ..
ninja
cp tools/spirv-as tools/spirv-dis tools/spirv-val tools/spirv-opt $OUT/
popd

mkdir SPIRV-Cross/build
pushd SPIRV-Cross/build
cmake -G "Ninja" -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_C_COMPILER=$CC -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" ..
ninja
cp spirv-cross $OUT/


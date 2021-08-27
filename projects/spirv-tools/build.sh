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

git clone https://github.com/KhronosGroup/SPIRV-Headers external/spirv-headers --depth=1
git clone https://github.com/protocolbuffers/protobuf   external/protobuf      --branch v3.13.0.1

mkdir build
cd build

CMAKE_ARGS="-DSPIRV_BUILD_LIBFUZZER_TARGETS=ON"

# With ubsan, RTTI must be enabled due to certain checks (vptr) requiring it.
if [ $SANITIZER == "undefined" ];
then
  CMAKE_ARGS="${CMAKE_ARGS} -DENABLE_RTTI=ON"
fi
cmake -G Ninja .. ${CMAKE_ARGS}
ninja

cp test/fuzzers/spvtools_*_fuzzer $OUT

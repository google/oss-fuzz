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

set -x

# build project
mkdir build
cd build
cmake ../ -B ./ -DSPM_ENABLE_SHARED=ON -DCMAKE_INSTALL_PREFIX=./root -DSPM_BUILD_TEST=ON
cmake --build ./ --config Release --target install --parallel $(nproc)

# build fuzzers
fuzzers=$(find $SRC -name '*_fuzzer.cc' | grep -v 'third_party')
echo "Found fuzzers: ${fuzzers[@]}"
for fuzzer in "${fuzzers[@]}"; do
  fuzz_basename=$(basename -s .cc $fuzzer)
  $CXX $CXXFLAGS -std=c++17 \
      -I. -I./root/include \
      $fuzzer $LIB_FUZZING_ENGINE \
      ./root/lib/*.a \
      -o $OUT/$fuzz_basename
done

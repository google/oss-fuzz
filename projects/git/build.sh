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

# build fuzzers
make -j$(nproc) CC=$CC CXX=$CXX CFLAGS="$CXXFLAGS" \
  LIB_FUZZING_ENGINE=$LIB_FUZZING_ENGINE fuzz-all

# copy fuzzers
for fuzzer in fuzz-pack-headers fuzz-pack-idx ; do
  cp $fuzzer $OUT
done

#!/bin/bash -eu
# Copyright 2023 Google LLC
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

cmake -S . -B build \
    -DXNNPACK_BUILD_BENCHMARKS=OFF \
    -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
    -DXNNPACK_BUILD_TESTS=ON \
    -DXNNPACK_LIBRARY_TYPE=static \
    -DXNNPACK_BUILD_FUZZERS=ON \
    -DLIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE"
cmake --build build --parallel 8
cp build/fuzz/fuzz_model "$OUT/fuzz_model"

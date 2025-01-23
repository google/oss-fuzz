#!/bin/bash -eu
# Copyright 2025 Google LLC
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

# Create build directory
mkdir build
cd build

SRC_DIR=/src/grass-addons
FUZZ_TARGET=$SRC_DIR/Fuzz/fuzz_target.c

$CXX $CXXFLAGS -I $SRC_DIR/include $FUZZ_TARGET -o $OUT/fuzz_target \
    $LIB_FUZZING_ENGINE $SRC_DIR/Fuzz/*.o
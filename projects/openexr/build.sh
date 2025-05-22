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

#
# Build the OpenEXR fuzzers, via the "oss_fuzz" CMake target.
#
# The "oss_fuzz" target is specially constructed to operate in this
# env. It queries the environment for the values of
# LIB_FUZZING_ENGINE, OUT, and CC/CC_FLAGS, and CXX/CXX_FLAGS. The
# installed fuzzers go in the OUT directory.
#

set -x

BUILD_DIR=$WORK/openexr/_build.oss-fuzz

cmake -S $SRC -B $BUILD_DIR --preset oss_fuzz
cmake --build $BUILD_DIR --target oss_fuzz -j"$(nproc)"
cmake --install $BUILD_DIR --component oss_fuzz


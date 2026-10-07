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

export BUILD_DIR=$WORK/_build.oss-fuzz

./src/test/oss-fuzz/oss-fuzz_build.sh

# Build tests to support replay_tests.sh
cd $BUILD_DIR
cmake --build $BUILD_DIR --target OpenEXRTest OpenEXRCoreTest IexTest OpenEXRUtilTest -j$(nproc)

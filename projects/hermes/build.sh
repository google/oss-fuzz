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

CONFIGURE_FLAGS="--oss-fuzz"
BUILD_DIR_SUFFIX=""
if [ "${SANITIZER}" = address ]
then
    CONFIGURE_FLAGS="${CONFIGURE_FLAGS} --enable-asan"
    BUILD_DIR_SUFFIX="_asan"
elif [ "${SANITIZER}" = undefined ]
then
    CONFIGURE_FLAGS="${CONFIGURE_FLAGS} --enable-ubsan"
    BUILD_DIR_SUFFIX="_ubsan"
fi

./utils/build/configure.py $OUT/build --oss-fuzz $CONFIGURE_FLAGS
cd $OUT/build${BUILD_DIR_SUFFIX}
ninja fuzzer
cp fuzzers/fuzzer $OUT

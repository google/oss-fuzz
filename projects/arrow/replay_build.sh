#!/bin/bash -eux
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

ARROW=${SRC}/arrow/cpp

BUILD_DIR=${SRC}/build-dir
cd ${BUILD_DIR}

# The CMake build setup compiles and runs the Thrift compiler, but ASAN
# would report leaks and error out.
export ASAN_OPTIONS="detect_leaks=0"

cmake --build . -j$(nproc)

# Copy fuzz targets
find . -executable -name "*-fuzz" -exec cp -a -v '{}' ${OUT} \;

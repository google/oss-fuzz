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

# build project
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DURIPARSER_OSSFUZZ_BUILD=ON \
      -DURIPARSER_BUILD_FUZZERS=ON \
      -DURIPARSER_BUILD_DOCS=OFF \
      -DURIPARSER_BUILD_TESTS=OFF \
      -DURIPARSER_BUILD_TOOLS=OFF \
      -DURIPARSER_ENABLE_INSTALL=OFF \
      ..
make
cp fuzz/*_fuzzer "$OUT/"

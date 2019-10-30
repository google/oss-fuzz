#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

mkdir build
cd build

cmake .. \
-GNinja \
-DCMAKE_BUILD_TYPE=Debug \
-DSIMDJSON_BUILD_STATIC=On \
-DCMAKE_CXX_STANDARD=14 \
-DENABLE_FUZZING=On \
-DSIMDJSON_FUZZ_LINKMAIN=Off \
-DSIMDJSON_FUZZ_LDFLAGS=$LIB_FUZZING_ENGINE

cmake --build .

cp bin/fuzzer_* $OUT


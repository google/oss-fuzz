#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# Build fuzzers
sed 's/static ?= no/LIB_CFLAGS += ${CXXFLAGS}\nstatic ?= no/g' -i Makefile
make static=yes -j$(nproc)
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    fuzz_sql_parse.cpp libsqlparser.a -I./src -o $OUT/fuzz_sql_parse

# Build unit tests
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-}:.
make bin/tests static=yes TEST_CFLAGS="-std=c++1z -Wall -Werror -Isrc/ -Itest/ -L./ $CXXFLAGS" -j$(nproc)

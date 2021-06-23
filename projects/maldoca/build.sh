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

# MALDOCA_DEFINES="-D_MALDOCA_CHROME=1"
# MALDOCA_WNOS="-Wno-sign-compare -Wno-error=unreachable-code"\ 
# "-Wno-unused-private-field  -Wno-c++98-compat-pedantic -Wno-comment"\ 
# "-Wno-ignored-qualifiers -Wno-unused-const-variable"
# MALDOCA_SRC_DIR = "$SRC/maldoca"

# $CXX $CXXFLAGS -std=c++11 -Iinclude \
#     /path/to/name_of_fuzzer.cc -o $OUT/name_of_fuzzer \
#     $LIB_FUZZING_ENGINE /path/to/library.a

bazel clean
bazel_build_fuzz_tests

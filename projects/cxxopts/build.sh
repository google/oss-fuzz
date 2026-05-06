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

# Disable ccache for chronos check since ccache is not compatible with bazel
export PATH=$(echo $PATH | tr ':' '\n' | grep -v ccache | tr '\n' ':' | sed 's/:$//')

export CXXFLAGS="${CXXFLAGS} -std=c++17"
export USE_BAZEL_VERSION=7.4.0
bazel_build_fuzz_tests

# Build unit test
$CXX $CXXFLAGS -o unittest -Iinclude -Itest test/main.cpp test/options.cpp

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

FUZZERS=("fuzz_dash_e")
PIPELINE_LIB=./bazel-bin/main/pipeline/libpipeline.a

# export CC=/bin/false
sed -i -e '/build --crosstool.*/d' .bazelrc
CXX="$CXX" CFLAGS="--std=c++17 --stdlib=libstdc++" CXXFLAGS="--std=c++17 --stdlib=libstdc++" bazel build --config=fuzz //test/fuzz:fuzz_dash_e

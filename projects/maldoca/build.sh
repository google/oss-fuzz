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

export BAZEL_EXTRA_BUILD_FLAGS="--copt=-DMALDOCA_CHROME=1 --define MALDOCA_CHROME=1 --repo_env=CC=clang --cxxopt=--std=c++14 --cxxopt=-Wno-unused-result --verbose_failures"

bazel clean
bazel_build_fuzz_tests

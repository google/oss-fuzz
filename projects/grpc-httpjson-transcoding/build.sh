#!/bin/bash -eu
#
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

# This project uses bazel rules_fuzzing. Script copied from OSS fuzz's bazel-rules-fuzzing-test.
# https://github.com/google/oss-fuzz/blob/62fce2a587b5d0eff941c392b343edfc68eb4069/projects/bazel-rules-fuzzing-test/build.sh

bazel_build_fuzz_tests

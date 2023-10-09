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
export USE_BAZEL_VERSION=5.4.0

# patch while waitin for https://github.com/google/tcmalloc/pull/191
sed -i 's/a5734cb42b1b69395c57e0bbd32ade394d5c3d6afbfe782b24816a96da24660d/23bb074064c6f488d12044934ab1b0631e8e6898d5cf2f6bde087adb01111573/g' ./WORKSPACE
sed -i 's/rules_fuzzing-0.1.1/rules_fuzzing-0.3.1/g' ./WORKSPACE
sed -i 's/rules_fuzzing\/archive\/v0.1.1.zip/rules_fuzzing\/archive\/v0.3.1.zip/g' ./WORKSPACE

bazel_build_fuzz_tests

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

# Due to https://github.com/bazelbuild/bazel/issues/11128, affecting Bazel 4.0
# or earlier, we cannot use the "@rules_fuzzing//" prefix for the label-typed
# cc_engine configuration flag when fuzzing directly the rules_fuzzing workspace.
#
# This is NOT needed for any other Bazel repository that depends on
# rules_fuzzing.
export BAZEL_EXTRA_BUILD_FLAGS="--//fuzzing:cc_engine=@rules_fuzzing_oss_fuzz//:oss_fuzz_engine"

bazel_build_fuzz_tests

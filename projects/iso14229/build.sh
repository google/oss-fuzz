#!/bin/bash -eu
# Copyright 2026 Google LLC
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

# The default query picks up additional dependencies which break the build.
# This query looks for `cc_fuzz_test` targets in the test/ directory.
export BAZEL_FUZZ_TEST_QUERY='let t = attr(generator_function, "^cc_fuzz_test$", attr(tags, "fuzz-test", //test/...)) in $t - attr(tags, "no-oss-fuzz", $t)'

export BAZEL_EXTRA_BUILD_FLAGS='--@rules_fuzzing//fuzzing:cc_engine=@rules_fuzzing//fuzzing/engines:oss_fuzz --@rules_fuzzing//fuzzing:java_engine=@rules_fuzzing//fuzzing/engines:oss_fuzz_java'

exec bazel_build_fuzz_tests

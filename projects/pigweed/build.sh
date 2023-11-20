#!/bin/bash

# Copyright 2020 Google Inc.
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
cd $SRC/pigweed

echo "Building project using Bazel wrapper."

export BAZEL_FUZZ_TEST_QUERY="
let all_fuzz_tests = attr(tags, \"fuzz-test\", \"//...\") in
let lang_fuzz_tests = attr(generator_function, \"pw_cc_fuzz_test\", \$all_fuzz_tests) in
\$lang_fuzz_tests - attr(tags, \"no-oss-fuzz\", \$lang_fuzz_tests)
"

bazel_build_fuzz_tests

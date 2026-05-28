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

# rules_fuzzing 0.6.0 (pinned in MODULE.bazel) generates an oss_fuzz BUILD
# that uses native cc_library, which was removed in Bazel 9. Override to a
# newer tag that loads cc_library from @rules_cc.
cat >> MODULE.bazel <<'EOF'

archive_override(
    module_name = "rules_fuzzing",
    urls = ["https://github.com/bazel-contrib/rules_fuzzing/archive/refs/tags/v0.7.0.tar.gz"],
    strip_prefix = "rules_fuzzing-0.7.0",
)

# .bazelrc's `non_hermetic` config references @local_config_cc_toolchains;
# under Bazel 9 + rules_cc 0.2.x this repo must be instantiated explicitly
# via the cc_configure extension.
cc_configure = use_extension("@rules_cc//cc:extensions.bzl", "cc_configure_extension")
use_repo(cc_configure, "local_config_cc_toolchains")
EOF

echo "Building project using Bazel wrapper."

export BAZEL_FUZZ_TEST_QUERY="
let all_fuzz_tests = attr(tags, \"fuzz-test\", \"//...\") in
let lang_fuzz_tests = attr(generator_function, \"pw_cc_fuzz_test\", \$all_fuzz_tests) in
\$lang_fuzz_tests - attr(tags, \"no-oss-fuzz\", \$lang_fuzz_tests)
"

export BAZEL_EXTRA_BUILD_FLAGS="
--config non_hermetic
--cxxopt=-std=c++17
--config=googletest
"

bazel_build_fuzz_tests

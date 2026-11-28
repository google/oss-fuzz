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

# Bazel 9 removed the native `cc_library` / `java_import` rules; they must now be
# loaded from @rules_cc / @rules_java. rules_fuzzing 0.6.0 (the version pinned by
# pigweed's MODULE.bazel) generates the @rules_fuzzing_oss_fuzz//:BUILD file for
# the OSS-Fuzz engine using those *native* rules without a load() statement, so
# analysis fails with "This rule has been removed from Bazel" under the Bazel 9
# toolchain used by OSS-Fuzz. rules_fuzzing 0.7.0+ fixes the template by adding
# the required load() statements. Bump the dependency to 0.8.0 to unbreak the
# build. This is exactly the fix pigweed's own MODULE.bazel anticipates:
#   TODO(b/370523804) / https://github.com/bazel-contrib/rules_fuzzing/issues/257
sed -i 's/name = "rules_fuzzing", version = "0.6.0"/name = "rules_fuzzing", version = "0.8.0"/' MODULE.bazel

# pigweed's .bazelrc `non_hermetic` config (which we enable below so OSS-Fuzz can
# inject its own fuzzing compilers) passes
# `--extra_toolchains=@local_config_cc_toolchains//...`. Under the Bazel 9
# toolchain used by OSS-Fuzz, that apparent repo name is only visible to a module
# that explicitly `use_repo`s it from rules_cc's cc_configure extension; pigweed's
# MODULE.bazel does not, so analysis fails with "No repository visible as
# '@local_config_cc_toolchains' from main repository". Make the repo visible.
cat >> MODULE.bazel <<'EOF'

# Added by OSS-Fuzz: expose the auto-detected system C++ toolchain repo so that
# `--config non_hermetic` can resolve --extra_toolchains=@local_config_cc_toolchains//...
cc_configure_ext = use_extension("@rules_cc//cc:extensions.bzl", "cc_configure_extension")
use_repo(cc_configure_ext, "local_config_cc_toolchains")
EOF

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

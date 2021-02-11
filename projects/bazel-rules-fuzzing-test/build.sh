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

# This is an example build script for projects using the rules_fuzzing library
# for Bazel. Use it as a starting point for your own integration.

# An easy way to build all the relevant fuzz tests for a project is to use a
# "bazel query" command. Here, we are collecting all fuzz test targets (which
# are tagged with "fuzz-test" by default). Here we also have a basic opt-out
# mechanism through the "no-oss-fuzz" tag. You can use additional filtering
# logic in your own integrations.
declare -r QUERY='
    let all_fuzz_tests = attr(tags, "fuzz-test", "//...") in
    $all_fuzz_tests - attr(tags, "no-oss-fuzz", $all_fuzz_tests)
'

# The fuzzing rules provide a special `<name>_oss_fuzz` target that creates a
# TAR archive with all the fuzz test artifacts (binary, corpus, dictionary,
# etc.) using the layout expected by OSS-Fuzz. We derive the OSS-Fuzz package
# targets from the fuzz test names using the "sed" command below.
declare -r PACKAGE_SUFFIX="_oss_fuzz"
declare -r OSS_FUZZ_TESTS="$(bazel query "${QUERY}" | sed "s/$/${PACKAGE_SUFFIX}/")"

# We now build all the OSS-Fuzz packages using the compiler toolchain provided 
# by OSS-Fuzz through $CC and $CXX. The `--config=oss-fuzz` flag takes care of
# using the correct instrumentation and fuzzing engine derived from the OSS-Fuzz
# environment.
bazel build -c opt --config=oss-fuzz --linkopt=-lc++ \
    --action_env=CC="${CC}" --action_env=CXX="${CXX}" \
    ${OSS_FUZZ_TESTS[*]}

# Finally, we extract the contents of the OSS-Fuzz packages directly into the
# $OUT/ directory. Recall that the packages already contain all the artifacts in
# the format expected by OSS-Fuzz.
for oss_fuzz_archive in $(find bazel-bin/ -name "*${PACKAGE_SUFFIX}.tar"); do
    tar -xvf "${oss_fuzz_archive}" -C "${OUT}"
done

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
export USE_BAZEL_VERSION="7.3.2"
export CC=${CC:-clang}
export CXX=${CXX:-clang++}

# modified version of bazel_build_fuzz_tests to work around issues with
# bzlmod dependency on rules_fuzzing

bazel build -c opt --config=oss-fuzz //fuzz:fuzz_parse_oss_fuzz

for oss_fuzz_archive in $(find bazel-bin/ -name "*oss_fuzz.tar"); do
    tar --no-same-owner -xvf "${oss_fuzz_archive}" -C "${OUT}"
done

if [ "$SANITIZER" = "coverage" ]; then
    echo "Collecting the repository source files for coverage tracking."
    declare -r COVERAGE_SOURCES="${OUT}/proc/self/cwd"
    mkdir -p "${COVERAGE_SOURCES}"
    declare -r RSYNC_FILTER_ARGS=(
        "--include" "*.h"
        "--include" "*.cc"
        "--include" "*.hpp"
        "--include" "*.cpp"
        "--include" "*.c"
        "--include" "*.inc"
        "--include" "*/"
        "--exclude" "*"
    )
    rsync -avLk "${RSYNC_FILTER_ARGS[@]}" \
        "$(bazel info execution_root)/" \
        "${COVERAGE_SOURCES}/"
fi
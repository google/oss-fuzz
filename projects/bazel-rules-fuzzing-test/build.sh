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

declare -r QUERY='
    let all_fuzz_tests = attr(tags, "fuzz-test", "//...") in
    $all_fuzz_tests - attr(tags, "no-oss-fuzz", $all_fuzz_tests)
'
declare -r PACKAGE_SUFFIX="_oss_fuzz"
declare -r OSS_FUZZ_TESTS="$(bazel query "${QUERY}" | sed "s/$/${PACKAGE_SUFFIX}/")"

bazel build -c opt --config=oss-fuzz --linkopt=-lc++ ${OSS_FUZZ_TESTS[*]}
for oss_fuzz_archive in $(find bazel-bin/ -name "*${PACKAGE_SUFFIX}.tar"); do
    tar -xvf "${oss_fuzz_archive}" -C "${OUT}"
done

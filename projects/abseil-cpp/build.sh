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

# Grep all unit test targets and only build them
mkdir $SRC/build-tests
pushd $SRC/build-tests
cmake -DABSL_BUILD_TESTING=ON $SRC/abseil-cpp
tests=$(make help | grep absl_ | grep test | awk '{print $2}')
make $tests -j$(nproc)
popd

# Disable ccache for chronos check since ccache is not compatible with bazel
export PATH=$(echo $PATH | tr ':' '\n' | grep -v ccache | tr '\n' ':' | sed 's/:$//')

export USE_BAZEL_VERSION=7.4.0
# Disable `layering_check` feature.
# As per https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=63223, it breaks
# the build. Someone could figure out exactly why it breaks the build, but just
# disabling it suffices because it doesn't actually matter for our purposes. ;)
# Also use C++17 as required by abseil-cpp.
export BAZEL_EXTRA_BUILD_FLAGS='--features=-layering_check --cxxopt=-std=c++17'
# The default query is complex and requires additional dependencies in order to
# work (due to its use of `//...`) whereas this query is simple and sufficient.
export BAZEL_FUZZ_TEST_QUERY='filter("_fuzzer$", //:all)'
exec bazel_build_fuzz_tests

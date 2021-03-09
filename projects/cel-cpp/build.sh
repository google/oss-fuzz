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

# build project
readonly EXTRA_BAZEL_FLAGS="$(
for f in ${CFLAGS}; do
  echo "--conlyopt=${f}" "--linkopt=${f}"
done
for f in ${CXXFLAGS}; do
  echo "--cxxopt=${f}" "--linkopt=${f}"
done

if [ "$SANITIZER" = "undefined" ]
then
  # Bazel uses clang to link binary, which does not link clang_rt ubsan library for C++ automatically.
  # See issue: https://github.com/bazelbuild/bazel/issues/8777
  echo "--linkopt=\"$(find $(llvm-config --libdir) -name libclang_rt.ubsan_standalone_cxx-x86_64.a | head -1)\""
fi
)"

declare FUZZ_TARGETS=("fuzz/fuzz_parse")

bazel build \
        --verbose_failures \
        --dynamic_mode=off \
        --spawn_strategy=standalone \
        --genrule_strategy=standalone \
        --strip=never \
        --linkopt=-pthread \
        --copt=${LIB_FUZZING_ENGINE} \
        --linkopt=${LIB_FUZZING_ENGINE} \
        --linkopt=-lc++ \
        ${EXTRA_BAZEL_FLAGS} \
        ${FUZZ_TARGETS[*]}

cp ./bazel-bin/fuzz/fuzz_parse $OUT/

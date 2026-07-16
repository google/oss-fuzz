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

# Work around https://github.com/bazelbuild/bazel/issues/21592: 
# The `layering_check` feature does not work with `--spawn_strategy=standalone`,
# which is the default for OSS-Fuzz builds.
AFLPP_RT=""
for f in /src/aflplusplus/afl-llvm-rt.o /src/aflplusplus/llvm_mode/afl-llvm-rt.o /src/aflplusplus/afl-compiler-rt.o; do
    if [ -f "$f" ]; then
        AFLPP_RT="$f"
        break
    fi
done
if [ -n "$AFLPP_RT" ]; then
    export BAZEL_EXTRA_BUILD_FLAGS="--spawn_strategy=sandboxed --linkopt=${AFLPP_RT}"
else
    export BAZEL_EXTRA_BUILD_FLAGS="--spawn_strategy=sandboxed"
fi

bazel_build_fuzz_tests

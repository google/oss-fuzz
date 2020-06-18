#!/bin/bash -eu
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

# This build.sh is partly modeled after that of envoyproxy:
# https://github.com/google/oss-fuzz/blob/master/projects/envoy/build.sh

export CFLAGS="$CFLAGS"
export CXXFLAGS="$CXXFLAGS"

# Copy $CFLAGS and $CXXFLAGS into Bazel command-line flags, for both
# compilation and linking.
#
# Some flags, such as `-stdlib=libc++`, generate warnings if used on a C source
# file. Since the build runs with `-Werror` this will cause it to break, so we
# use `--conlyopt` and `--cxxopt` instead of `--copt`.
declare -r EXTRA_BAZEL_FLAGS="$(
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

# Temporary hack, see https://github.com/google/oss-fuzz/issues/383
readonly NO_VPTR='--copt=-fno-sanitize=vptr --linkopt=-fno-sanitize=vptr'

declare FUZZER_PATH="zetasql/fuzzing/simple_evaluator_fuzzer"
declare FUZZ_TARGET="//zetasql/fuzzing:simple_evaluator_fuzzer"

# Build fuzz target
# see https://google.github.io/oss-fuzz/further-reading/fuzzer-environment/
bazel-1.0.0 build -s --verbose_failures --compilation_mode=dbg \
  --dynamic_mode=off \
  --spawn_strategy=standalone \
  --genrule_strategy=standalone \
  --conlyopt=-Wno-error=c99-extensions \
  --copt -D__OSS_FUZZ__ \
  --copt -fno-sanitize-blacklist \
  --linkopt=--rtlib=compiler-rt \
  --linkopt=--unwindlib=libunwind \
  --linkopt=-lc++ \
  --linkopt="-rpath '\$ORIGIN\/lib'" \
  --define LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE} \
  ${EXTRA_BAZEL_FLAGS} ${NO_VPTR} \
  ${FUZZ_TARGET}

# Move out dynamically linked libraries
mkdir -p $OUT/lib
cp /usr/lib/x86_64-linux-gnu/libunwind.so.8 $OUT/lib/

# Move out tzdata
# See also https://github.com/googleinterns/zetasql-fuzzing/pull/3
mkdir -p $OUT/data
cp -r /usr/share/zoneinfo $OUT/data/

# Move out fuzz target
cp bazel-bin/"${FUZZER_PATH}" "${OUT}"/

# Cleanup bazel- symlinks to avoid oss-fuzz trying to copy out of the build
# cache.
rm -f bazel-*

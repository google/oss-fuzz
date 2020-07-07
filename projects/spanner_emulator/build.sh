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

export CFLAGS="$CFLAGS"
export CXXFLAGS="$CXXFLAGS"

declare -r FUZZER_TARGETS_CC=$(find . -name *_fuzz_test.cc)
declare -r FUZZER_TARGETS="$(for t in ${FUZZER_TARGETS_CC}; do echo "${t:2:-3}"; done)"

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
)"

declare BAZEL_TARGET_PATH="k8-fastbuild/bin/src/fuzz"
declare BAZEL_BUILD_TARGETS="//src/fuzz:all"

# Temporary hack, see https://github.com/google/oss-fuzz/issues/383
readonly NO_VPTR='--copt=-fno-sanitize=vptr --linkopt=-fno-sanitize=vptr'

# Build driverless libraries.
bazel build --verbose_failures  --strip=never \
  --dynamic_mode=off \
  --copt=-fno-sanitize=vptr \
  --linkopt=-fno-sanitize=vptr \
  --copt -D__SANITIZE_ADDRESS__ \
  --copt -D__OSS_FUZZ__ \
  --copt -fno-sanitize-blacklist \
  --cxxopt="-stdlib=libc++" \
  --linkopt="--rtlib=compiler-rt" \
  --linkopt="--unwindlib=libunwind" \
  --linkopt="-stdlib=libc++" \
  --linkopt="-lc++" \
  --linkopt=-pthread ${EXTRA_BAZEL_FLAGS} \
  --define LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE} \
  --linkopt="-rpath '\$ORIGIN\/lib'" \
  ${NO_VPTR} \
  ${EXTRA_BAZEL_FLAGS} \
  ${BAZEL_BUILD_TARGETS[*]}

# Move out dynamically linked libraries
mkdir -p $OUT/lib
cp /usr/lib/x86_64-linux-gnu/libunwind.so.8 $OUT/lib/

# Move out tzdata
mkdir -p $OUT/data
cp -r /usr/share/zoneinfo $OUT/data/

# Move out fuzz target
cp "${SRC}"/fuzz/bazel-out/"${BAZEL_TARGET_PATH}"/*_fuzz_test "${OUT}"/

# Cleanup bazel- symlinks to avoid oss-fuzz trying to copy out of the build
# cache.
rm -f bazel-*

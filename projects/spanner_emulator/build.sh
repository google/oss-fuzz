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

# build project
# e.g.
# ./autogen.sh
# ./configure
# make -j$(nproc) all

# build fuzzers
# e.g.
# $CXX $CXXFLAGS -std=c++11 -Iinclude \
#     /path/to/name_of_fuzzer.cc -o $OUT/name_of_fuzzer \
#     $LIB_FUZZING_ENGINE /path/to/library.a



export CFLAGS="$CFLAGS"
export CXXFLAGS="$CXXFLAGS"
echo "beginning!!!!!!!!!!!!!!!!!!!!!!!!!!1"
eval "ls"

declare -r FUZZER_TARGETS_CC=$(find . -name *_fuzz_test.cc)
declare -r FUZZER_TARGETS="$(for t in ${FUZZER_TARGETS_CC}; do echo "${t:2:-3}"; done)"

FUZZER_DICTIONARIES="\
"

# Copy $CFLAGS and $CXXFLAGS into Bazel command-line flags, for both
# compilation and linking.
#
# Some flags, such as `-stdlib=libc++`, generate warnings if used on a C source
# file. Since the build runs with `-Werror` this will cause it to break, so we
# use `--conlyopt` and `--cxxopt` instead of `--copt`.
#
# NOTE: We ignore -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION. All envoy fuzz
# targets link this flag through their build target rule. Passing this in via CLI
# will pass this to genrules that build unit tests that rely on production
# behavior. Ignore this flag so these unit tests don't fail by using a modified
# RE2 library.
# TODO(asraa): Figure out how to work around this better.
CFLAGS=${CFLAGS//"-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"/}
CXXFLAGS=${CXXFLAGS//"-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"/}
declare -r EXTRA_BAZEL_FLAGS="$(
for f in ${CFLAGS}; do
  echo "--conlyopt=${f}" "--linkopt=${f}"
done
for f in ${CXXFLAGS}; do
  echo "--cxxopt=${f}" "--linkopt=${f}"
done
)"

declare BAZEL_BUILD_TARGETS="//src/fuzz:all"



# Build driverless libraries.
bazel build --verbose_failures --dynamic_mode=off --spawn_strategy=standalone \
  --genrule_strategy=standalone --strip=never \
  --copt=-fno-sanitize=vptr --linkopt=-fno-sanitize=vptr \
  --copt -D__SANITIZE_ADDRESS__ \
  --build_tag_filters=-no_asan \
  --cxxopt="-stdlib=libc++" --linkopt="--rtlib=compiler-rt" \
  --linkopt="--unwindlib=libunwind" --linkopt="-stdlib=libc++" \
  --linkopt="-lc++" --linkopt=-pthread ${EXTRA_BAZEL_FLAGS} \
  ${BAZEL_BUILD_TARGETS[*]}
  
# Copy dictionaries and options files to $OUT/
for d in $FUZZER_DICTIONARIES; do
  cp "$d" "${OUT}"/
done

# Cleanup bazel- symlinks to avoid oss-fuzz trying to copy out of the build
# cache.
rm -f bazel-*

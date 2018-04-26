#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# Disable UBSan vptr since target built with -fno-rtti.
export CFLAGS="$CFLAGS -fno-sanitize=vptr"
export CXXFLAGS="$CXXFLAGS -fno-sanitize=vptr"

declare -r FUZZER_TARGETS_CC=$(find . -name *_fuzz_test.cc)
declare -r FUZZER_TARGETS="$(for t in ${FUZZER_TARGETS_CC}; do echo "${t:2:-3}"; done)"

FUZZER_DICTIONARIES="\
"

# Skip gperftools, ASAN runs don't use tcmalloc.
export DISABLE_GPERFTOOLS_BUILD=1
sed -i 's#envoy_dependencies()#envoy_dependencies(skip_targets=["tcmalloc_and_profiler"])#' WORKSPACE

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

# Build Envoy
declare -r BAZEL_BUILD_TARGETS="$(for t in ${FUZZER_TARGETS}; do \
  echo //"$(dirname "$t")":"$(basename "$t")_driverless"; done)"
bazel build --verbose_failures --dynamic_mode=off --spawn_strategy=standalone \
  --genrule_strategy=standalone --strip=never \
  --copt=-fno-sanitize=vptr --linkopt=-fno-sanitize=vptr \
  --define tcmalloc=disabled --define signal_trace=disabled \
  --define ENVOY_CONFIG_ASAN=1 --copt -D__SANITIZE_ADDRESS__ \
  --define force_libcpp=enabled \
  --build_tag_filters=-no_asan --test_tag_filters=-no_asan \
  ${EXTRA_BAZEL_FLAGS} \
  --linkopt="-lFuzzingEngine" \
  ${BAZEL_BUILD_TARGETS[*]}

# Copy out test binaries from bazel-bin/ and zip up related test corpuses.
for t in ${FUZZER_TARGETS}
do
  TARGET_BASE="$(expr "$t" : '.*/\(.*\)_fuzz_test')"
  cp bazel-bin/"${t}"_driverless "${OUT}"/"${TARGET_BASE}"_fuzz_test
  zip "${OUT}/${TARGET_BASE}"_fuzz_test_seed_corpus.zip \
    "$(dirname "${t}")"/"${TARGET_BASE}"_corpus/*
done

# Copy dictionaries and options files to $OUT/
for d in $FUZZER_DICTIONARIES; do
  cp "$d" "${OUT}"/
done

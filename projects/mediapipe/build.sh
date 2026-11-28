#!/bin/bash -eu
# Copyright 2026 Google LLC
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

cd $SRC/mediapipe

# Force libc++ for both target and host bazel compiles. The OSS-Fuzz
# base-builder image's default host stdlib (libstdc++ from gcc-9 on Ubuntu
# 20.04) lacks the <compare> C++20 header that mediapipe's pinned abseil
# requires; the image's clang-22 + libc++ supports it cleanly.
export BAZEL_EXTRA_BUILD_FLAGS="\
  --cxxopt=-stdlib=libc++ \
  --linkopt=-stdlib=libc++ \
  --host_cxxopt=-stdlib=libc++ \
  --host_linkopt=-stdlib=libc++ \
  --define=MEDIAPIPE_DISABLE_GPU=1"

# Discover all cc_fuzz_test targets across mediapipe and build their
# rules_fuzzing-generated _oss_fuzz packaging targets, placing fuzzer binaries
# in $OUT/. The wrapper handles instrumentation flags, sanitizer linkage, and
# corpus packaging automatically when used with rules_fuzzing.
bazel_build_fuzz_tests

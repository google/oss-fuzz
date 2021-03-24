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
git apply ../../patch.diff
unset CFLAGS
unset CXXFLAGS
utils/build-script --skip-build-benchmarks \
  --skip-ios --skip-watchos --skip-tvos --swift-darwin-supported-archs "x86_64" \
  --release-debuginfo --enable-sanitize-coverage --enable-asan
cp ../build/Ninja-RelWithDebInfoAssert/swift-linux-x86_64/bin/*fuzzer $OUT/

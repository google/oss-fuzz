#!/bin/bash -eu
# Copyright 2025 Google LLC
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

# Apply diff
git apply $SRC/build.diff

# Prepare fuzzer in gn directory
mkdir src/fuzz
cp $SRC/*.cc src/fuzz/

# Retrieve and build dependencies
./build/install-build-deps.sh --no-prompt

# Generate ninja file for build
gn gen out/fuzz --args="treat_warnings_as_errors=false is_component_build=false libcxx_is_shared=false"

# Build binary
autoninja -C out/fuzz fuzz_sha1

# Copy binary to $OUT
cp ./out/fuzz/fuzz_sha1 $OUT

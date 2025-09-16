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

# Fix sanitizer
ORIGINAL_SANITIZER="${SANITIZER:-}"

if [ "$SANITIZER" = "coverage" ] || [ "$SANITIZER" = "introspector" ] || [ "$SANITIZER" = "none" ]; then
    export SANITIZER="address"
fi

# Configure arguments for gn build
ARGS="treat_warnings_as_errors=false is_component_build=false libcxx_is_shared=false is_debug=false"
ARGS+=" use_custom_libcxx=false use_sysroot=true ozone_platform_x11=false"
ARGS+=" is_clang=true clang_use_chrome_plugins=false clang_base_path=\"/usr/local\""

# Configure arguments for gn build
if [ "$SANITIZER" = "undefined" ]; then
    ARGS="$ARGS is_ubsan=true"
fi

# Prepare fuzzer in gn directory
mkdir -p src/fuzz
cp $SRC/*.cc src/fuzz/

# Generate ninja file for build
gn gen out/fuzz --args="$ARGS"
echo $SANITIZER
# Build binary
autoninja -C out/fuzz fuzz_sha1
autoninja -C out/fuzz fuzz_translator

# Copy binary to $OUT
cp ./out/fuzz/fuzz_sha1 $OUT
cp ./out/fuzz/fuzz_translator $OUT

# Reset sanitizer
if [ -n "$ORIGINAL_SANITIZER" ]; then
    export SANITIZER="$ORIGINAL_SANITIZER"
fi

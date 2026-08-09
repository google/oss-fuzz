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

# Hack to fix clang version mismatch
# The build system somehow thinks clang version is 23, but it's 22 in /usr/local
if [ ! -d /usr/local/lib/clang/23 ]; then
    ln -s /usr/local/lib/clang/22 /usr/local/lib/clang/23 || true
fi

# Remove flags not supported by OSS-Fuzz's clang version
sed -i '/-fdiagnostics-show-inlining-chain/d' build/config/compiler/BUILD.gn
sed -i '/-fno-lifetime-dse/d' build/config/compiler/BUILD.gn
sed -i '/-Wa,--crel,--allow-experimental-crel/d' build/config/compiler/BUILD.gn
# Also handle the ubsan ignore flags in sanitizers.gni
sed -i '/-fsanitize-ignore-for-ubsan-feature=${invoker.sanitizer}/d' build/config/sanitizers/sanitizers.gni

# Configure arguments for gn build
ARGS="treat_warnings_as_errors=false is_component_build=false libcxx_is_shared=false is_debug=false"
ARGS+=" use_custom_libcxx=true use_sysroot=true ozone_platform_x11=false"
ARGS+=" is_clang=true clang_use_chrome_plugins=false clang_base_path=\"/usr/local\""
# Enable MSL and WGSL translators specifically, without enabling the full Metal renderer
ARGS+=" angle_enable_msl=true angle_enable_wgpu=true"

# Configure arguments for gn build
if [ "$SANITIZER" = "undefined" ]; then
    ARGS="$ARGS is_ubsan=true"
fi

# Prepare fuzzer in gn directory
mkdir -p src/fuzz
cp $SRC/*.cc src/fuzz/

# Generate ninja file for build
gn gen out/fuzz --args="$ARGS"

# Build binary
autoninja -C out/fuzz fuzz_sha1
autoninja -C out/fuzz fuzz_translator
autoninja -C out/fuzz fuzz_spirv_transform
autoninja -C out/fuzz fuzz_spirv_parser
autoninja -C out/fuzz fuzz_preprocessor

# Copy binary to $OUT
cp ./out/fuzz/fuzz_sha1 $OUT
cp ./out/fuzz/fuzz_translator $OUT
cp ./out/fuzz/fuzz_spirv_transform $OUT
cp ./out/fuzz/fuzz_spirv_parser $OUT
cp ./out/fuzz/fuzz_preprocessor $OUT

# Reset sanitizer
if [ -n "$ORIGINAL_SANITIZER" ]; then
    export SANITIZER="$ORIGINAL_SANITIZER"
fi

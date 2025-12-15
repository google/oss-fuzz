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

# Configure arguments for gn build
ARGS='is_asan = true
 is_component_build = false
 use_clang_modules = false
 symbol_level = 2
 forbid_non_component_debug_builds = false
 use_debug_fission = false
 use_dwarf5 = true
 target_cpu = "x64"
 target_os = "linux"
 use_reclient = false
 use_remoteexec = false
 use_siso = false
 treat_warnings_as_errors = false
 libcxx_is_shared = false
 v8_enable_backtrace = true
 v8_enable_slow_dchecks = true
 v8_enable_test_features = true
 v8_enable_fast_mksnapshot = false'

if [[ -n "${INDEXER_BUILD:-}" ]]; then
  ARGS="$ARGS is_debug=true v8_optimized_debug=false v8_enable_slow_dchecks=true clang_base_path=\"/opt/toolchain\""
else
  ARGS="$ARGS is_debug=false v8_enable_slow_dchecks=false"
fi

# Generate ninja file for build
gn gen out/fuzz --args="$ARGS"
echo $SANITIZER

# Force re-linking.
rm -f out/fuzz/d8

# Build binary
ninja -C out/fuzz d8 -j$(nproc)

# Copy binary to $OUT
cp ./out/fuzz/{d8,snapshot_blob.bin} $OUT

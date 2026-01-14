#!/bin/bash -eu
#
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
#
################################################################################

# Disable leak sanitizer
export ASAN_OPTIONS="detect_leaks=0"

# Run unit testing, skipping some that requires hardware or network configuration
meson test -C $WORK/build --suite rauc -j$(nproc) artifacts bootchooser checksum config_file context event_log hash_index manifest progress slot stats status_file utils

# Test skipped that requires hardware or network configuration
# meson test -C $WORK/build --suite rauc -j$(nproc) boot_raw_fallback bundle dm install service signature update_handler

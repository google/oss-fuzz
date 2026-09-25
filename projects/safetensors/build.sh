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
#
################################################################################
cd "$SRC/safetensors/safetensors"

# The fuzz targets live in the upstream repository (safetensors/fuzz), so this
# builds whatever that crate declares rather than pinning names here.
cargo fuzz build -O --debug-assertions

FUZZ_RELEASE="fuzz/target/x86_64-unknown-linux-gnu/release"
for target in $(cargo fuzz list); do
  cp "$FUZZ_RELEASE/$target" "$OUT/"
done

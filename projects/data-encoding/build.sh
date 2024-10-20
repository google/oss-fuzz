#!/bin/bash -eu
# Copyright 2024 Google LLC
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

# Apply diff for lib/fuzz/Cargo.toml to include v3-preview feature for fuzzing
git apply $SRC/patch.diff

# Build the fuzzers and project source code
cd lib
cargo fuzz build -O

# Copy built fuzzer binaries to $OUT
cp $SRC/data-encoding/target/x86_64-unknown-linux-gnu/release/encoder $OUT
cp $SRC/data-encoding/target/x86_64-unknown-linux-gnu/release/encode_write $OUT
cp $SRC/data-encoding/target/x86_64-unknown-linux-gnu/release/round_trip $OUT
cp $SRC/data-encoding/target/x86_64-unknown-linux-gnu/release/v3-preview $OUT

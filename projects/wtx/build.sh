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

cd "$SRC/wtx"

export CARGO_TARGET_DIR="$SRC/wtx/target"

fuzz_dir="wtx-fuzz"
fuzz_target_dir="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"

ln -sfn "$fuzz_dir" fuzz
cargo fuzz build -O --fuzz-dir "$fuzz_dir"

for target_source in "$fuzz_dir"/*.rs; do
  target="$(basename "$target_source" .rs)"
  cp "$fuzz_target_dir/$target" "$OUT/"
done

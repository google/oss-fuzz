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

# Builds every target in fuzz/ and packages seed corpora from the checked-in fixtures.
cd "$SRC/rust-compress"
cargo fuzz build -O --fuzz-dir fuzz

TARGET_DIR="fuzz/target/x86_64-unknown-linux-gnu/release"
for target in inflate png jpeg_decode jpeg_coefs webp gif avif av1_obu; do
  cp "$TARGET_DIR/$target" "$OUT/$target"
done

seed() { # seed <target> <glob...>
  local name=$1; shift
  zip -qj "$OUT/${name}_seed_corpus.zip" "$@"
}
seed inflate     fixtures/*.png
seed png         fixtures/*.png
seed jpeg_decode fixtures/*.jpg
seed jpeg_coefs  fixtures/*.jpg
seed webp        fixtures/*.webp
seed gif         fixtures/*.gif
seed avif        fixtures/*.avif
seed av1_obu     fixtures/*.obu

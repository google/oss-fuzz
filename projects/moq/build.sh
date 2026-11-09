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

# Fat LTO drops sanitizer coverage globals; stripping hides crash symbols.
export CARGO_PROFILE_RELEASE_LTO=false
export CARGO_PROFILE_RELEASE_STRIP=none
export CARGO_TARGET_DIR="$WORK/target"

for crate in moq-net moq-quic; do
  cd "$SRC/moq/rs/$crate"

  # The generator runs during the build, outside the fuzzing runtime.
  env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u CFLAGS -u CXXFLAGS \
    cargo run --locked -p "$crate" --features fuzz --example fuzz-seeds -- \
    "$WORK/seeds/$crate"

  # Running beside fuzz/ also supports OSS-Fuzz's coverage Cargo wrapper.
  cargo fuzz build -O --debug-assertions

  for source in fuzz/fuzz_targets/*.rs; do
    target=$(basename "$source" .rs)
    cp "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/$target" "$OUT/"
    zip -j "$OUT/${target}_seed_corpus.zip" "$WORK/seeds/$crate/$target/"*
  done
done

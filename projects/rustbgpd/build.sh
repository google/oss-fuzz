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

# rustbgpd carries one cargo-fuzz crate per fuzzed workspace crate.
# Target names are globally unique across the four directories.
FUZZ_DIRS="crates/wire crates/policy crates/evpn crates/mrt"
TARGET_DIR="fuzz/target/x86_64-unknown-linux-gnu/release"

for dir in $FUZZ_DIRS; do
  pushd "$SRC/rustbgpd/$dir"
  cargo fuzz build -O --debug-assertions
  for f in fuzz/fuzz_targets/*.rs; do
    name=$(basename "${f%.rs}")
    cp "$TARGET_DIR/$name" "$OUT/"
    # Ship the in-tree seed corpus when one exists.
    if [ -d "fuzz/seeds/$name" ]; then
      zip -jr "$OUT/${name}_seed_corpus.zip" "fuzz/seeds/$name"
    fi
  done
  popd
done

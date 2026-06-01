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

cd "$SRC/provii-crypto/fuzz"

# Build every fuzz target defined in fuzz/Cargo.toml.
cargo fuzz build -O

FUZZ_TARGET_DIR="$SRC/provii-crypto/fuzz/target/x86_64-unknown-linux-gnu/release"

# Enumerate targets directly from Cargo.toml via `cargo fuzz list` so this
# script can never drift out of sync with the [[bin]] entries. Each target is
# copied to $OUT, along with a seed corpus when one is committed under
# fuzz/corpus/<target>/.
for target in $(cargo fuzz list); do
    if [ ! -f "$FUZZ_TARGET_DIR/$target" ]; then
        echo "Error: $target not found in $FUZZ_TARGET_DIR" >&2
        exit 1
    fi
    cp "$FUZZ_TARGET_DIR/$target" "$OUT/"

    corpus_dir="corpus/$target"
    if [ -d "$corpus_dir" ] && [ -n "$(ls -A "$corpus_dir" 2>/dev/null)" ]; then
        zip -j "$OUT/${target}_seed_corpus.zip" "$corpus_dir"/*
    fi
done

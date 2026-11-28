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

cd "$SRC/nextzip"

# The fuzz crate is its own workspace (fuzz/Cargo.toml) with the same
# [patch.crates-io] entries as the main workspace.
cargo fuzz build -O --fuzz-dir fuzz

# Every [[bin]] in fuzz/Cargo.toml, so new targets are picked up automatically.
TARGETS="$(cargo fuzz list --fuzz-dir fuzz)"
BIN_DIR="fuzz/target/x86_64-unknown-linux-gnu/release"

for t in $TARGETS; do
    cp "$BIN_DIR/$t" "$OUT/"
    if [ -d "fuzz/corpus/$t" ] && [ -n "$(ls -A "fuzz/corpus/$t")" ]; then
        (cd "fuzz/corpus/$t" && zip -q -r "$OUT/${t}_seed_corpus.zip" .)
    fi
    # Archive inputs can be large; give libFuzzer room for them.
    printf '[libfuzzer]\nmax_len = 1048576\n' > "$OUT/$t.options"
done

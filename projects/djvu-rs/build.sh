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

cd $SRC/djvu-rs

# Each target lives at fuzz/fuzz_targets/<name>.rs and is registered in
# fuzz/Cargo.toml. OSS-Fuzz's Rust base image configures sanitizer flags via
# the environment; cargo-fuzz builds all registered targets with those flags.
# Keep in sync with fuzz/Cargo.toml and the table in oss-fuzz/README.md.
TARGETS="fuzz_full fuzz_iff fuzz_jb2 fuzz_bzz fuzz_iw44 fuzz_encode fuzz_bzz_encode
         fuzz_g4 fuzz_metadata fuzz_graph fuzz_validate"

cargo fuzz build -O
fuzz_out=fuzz/target/x86_64-unknown-linux-gnu/release
for target in $TARGETS; do
    cp "$fuzz_out/$target" "$OUT/$target"
done

# Seed corpora — OSS-Fuzz convention: $OUT/<target>_seed_corpus.zip is
# unpacked into the per-target corpus dir on the first run. We ship the
# in-tree fuzz/corpus/<target>/ contents which are all small (< 200 KB
# each, < 1 MB total) and CC0/synthetic.
for target in $TARGETS; do
    if [ -d "fuzz/corpus/$target" ] && [ -n "$(ls -A fuzz/corpus/$target 2>/dev/null)" ]; then
        (cd "fuzz/corpus/$target" && zip -qr "$OUT/${target}_seed_corpus.zip" .)
    fi
done

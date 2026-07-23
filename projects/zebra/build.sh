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

#
# OSS-Fuzz build script for the Zebra fuzz target suite.
# Runs inside the base-builder-rust container; $OUT / $SRC / $CC / $CXX /
# $LIB_FUZZING_ENGINE are provided by the build environment.

# The repo is cloned to $SRC/zebra-fuzz by the Dockerfile.
# Non-standard layout: the cargo-fuzz harnesses live at zebra-fuzz/fuzz/, NOT at
# the workspace root. cargo-fuzz must run from the workspace root WITH
# --fuzz-dir; otherwise it resolves the manifest to the (non-existent)
# workspace-root fuzz/ and dies with "could not read manifest .../fuzz/Cargo.toml".
cd "$SRC/zebra-fuzz"

# The OSS-Fuzz coverage build's cargo wrapper hard-codes `cd fuzz` (verified by
# reading /usr/local/bin/cargo in the image: `cd fuzz || true; cargo build --bins`),
# ignoring --fuzz-dir. Symlink fuzz -> zebra-fuzz/fuzz BEFORE the build so the
# wrapper's `cd fuzz` resolves to the bin targets instead of editing nothing at
# the workspace root. The address/default build uses --fuzz-dir, unaffected.
ln -sfn zebra-fuzz/fuzz fuzz

# Zebra pins rust-toolchain.toml to a STABLE channel (the zebrad MSRV), but
# cargo-fuzz needs nightly for -Zsanitizer. base-builder-rust defaults to
# nightly, but the repo's stable pin can win and break the build with
# "error: 1 nightly option were parsed". Force nightly so the build is robust.
export RUSTUP_TOOLCHAIN=nightly

# -O builds the fuzzers in release mode (the OSS-Fuzz Rust convention).
cargo fuzz build -O --fuzz-dir zebra-fuzz/fuzz

FUZZ_OUT="zebra-fuzz/fuzz/target/x86_64-unknown-linux-gnu/release"

# Explicit white-list — only the 15 shipped targets (M1 5 + M2 7 + M3 3 Ironwood)
# are copied to $OUT. We do NOT glob fuzz/fuzz_targets/*.rs, so no held-back /
# out-of-scope target can leak into the published fuzzer set.
WHITELIST=(
    # M2 (7)
    rpc_handler_fuzz
    jsonrpsee_envelope_fuzz
    script_verify_fuzz
    script_flag_matrix_fuzz
    address_fuzz
    note_commitment_tree_fuzz
    equihash_fuzz
    # M1 (5)
    block_deserialize
    block_deep_fuzz
    p2p_message_parse
    p2p_deep_fuzz
    addr_message_fuzz
    # M3 Ironwood (3)
    v6_transaction_fuzz
    v6_transaction_semantic_fuzz
    ironwood_value_balance_codec_fuzz
)

for t in "${WHITELIST[@]}"; do
    cp "$FUZZ_OUT/$t" "$OUT/"
    # Ship a seed corpus alongside each target if one was staged under
    # fuzz/corpus/<target>/ (mainnet-derived public bytes; safe to publish).
    if [ -d "zebra-fuzz/fuzz/corpus/$t" ]; then
        (cd "zebra-fuzz/fuzz/corpus/$t" && zip -q -r "$OUT/${t}_seed_corpus.zip" .)
    fi
    # Ship a dictionary if one exists under zebra-fuzz/fuzz/dicts/<target>.dict.
    if [ -f "zebra-fuzz/fuzz/dicts/${t}.dict" ]; then
        cp "zebra-fuzz/fuzz/dicts/${t}.dict" "$OUT/${t}.dict"
    fi
done

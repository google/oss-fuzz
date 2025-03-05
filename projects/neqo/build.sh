#!/bin/bash -eu

cd "$SRC/neqo"
cargo fuzz build -O --debug-assertions

FUZZ_TARGET_OUTPUT_DIR=target/x86_64-unknown-linux-gnu/release
for f in fuzz/fuzz_targets/*.rs; do
        FUZZ_TARGET_NAME=$(basename "${f%.*}")
        cp "$FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME" "$OUT/"
done

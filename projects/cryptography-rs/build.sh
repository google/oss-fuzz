#!/bin/bash -eu

cd "$SRC/cryptography"
cargo fuzz build -O

for f in fuzz/fuzz_targets/*.rs; do
    FUZZ_TARGET=$(basename "${f%.*}")
    cp "fuzz/target/x86_64-unknown-linux-gnu/release/$FUZZ_TARGET" "$OUT/"
done

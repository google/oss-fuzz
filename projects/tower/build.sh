#!/bin/bash -eu
cd $SRC/tower
cargo fuzz build -O --debug-assertions
cp fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_parse $OUT/

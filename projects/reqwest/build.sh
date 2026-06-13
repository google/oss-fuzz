#!/bin/bash -eu
cd $SRC/reqwest
cargo fuzz build -O --debug-assertions
cp fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_url /

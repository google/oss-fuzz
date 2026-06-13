#!/bin/bash -eu
cd $SRC/actix-web
cargo fuzz build -O --debug-assertions
cp fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_header_parse $OUT/
cp fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_uri_parse $OUT/

#!/bin/bash

set -eux

# https://google.github.io/oss-fuzz/getting-started/new-project-guide/#buildsh
OUT=${OUT:-out}
mkdir -p "$OUT"

build_type=${1:-"release"}
build_args="--release"
if [[ "$build_type" =~ "dev" ]]; then
    build_type="debug"
    build_args="--dev"
fi

cargo fuzz build $build_args --debug-assertions --verbose
cp "fuzz/target/x86_64-unknown-linux-gnu/$build_type/fuzz_pulldown_cmark_read" $OUT/

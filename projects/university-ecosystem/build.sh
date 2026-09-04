#!/bin/bash
# OSS-Fuzz build script for university-ecosystem (pyo3-sanitizer fuzz targets)
# See: https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/
set -e

cd "$SRC/university_ecosystem"

# Build all cargo-fuzz targets
cargo fuzz build --release

# Copy compiled fuzz binaries to $OUT
FUZZ_TARGET_DIR="target/x86_64-unknown-linux-gnu/release"
for fuzzer in $(cargo fuzz list); do
    if [ -f "$FUZZ_TARGET_DIR/$fuzzer" ]; then
        cp "$FUZZ_TARGET_DIR/$fuzzer" "$OUT/"
    fi
done

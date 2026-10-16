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

cd $SRC/cel-rust

cp fuzz/Cargo.toml fuzz/Cargo.toml.bak
cleanup() {
    mv -f fuzz/Cargo.toml.bak fuzz/Cargo.toml || true
    rm -f fuzz/fuzz_targets/fuzz_pratt_parser.rs
}
trap cleanup EXIT

cp $SRC/fuzz_pratt_parser.rs fuzz/fuzz_targets/fuzz_pratt_parser.rs

if ! grep -q "parser_pratt" fuzz/Cargo.toml; then
    sed -i '/\[dependencies\.cel\]/a features = ["parser_pratt"]' fuzz/Cargo.toml
fi

if ! grep -q 'name = "fuzz_pratt_parser"' fuzz/Cargo.toml; then
    cat << 'TOML' >> fuzz/Cargo.toml

[[bin]]
name = "fuzz_pratt_parser"
path = "fuzz_targets/fuzz_pratt_parser.rs"
test = false
doc = false
bench = false
TOML
fi

cargo fuzz build -O --sanitizer $SANITIZER

FUZZ_TARGET_OUTPUT_DIR=target/x86_64-unknown-linux-gnu/release
for f in fuzz/fuzz_targets/*.rs; do
    FUZZ_TARGET_NAME=$(basename ${f%.*})
    cp $FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME $OUT/
done

cp $SRC/fuzz_pratt_parser.options $OUT/

#!/bin/bash -eu
# Copyright 2024 Google LLC
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

# Build rustledger-parser fuzz targets
cd $SRC/rustledger/crates/rustledger-parser
cargo +nightly fuzz build --release

# Copy parser fuzz targets to output
cp fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_parse $OUT/
cp fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_parse_line $OUT/

# Build rustledger-query fuzz targets
cd $SRC/rustledger/crates/rustledger-query
cargo +nightly fuzz build --release

# Copy query fuzz targets to output
cp fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_query_parse $OUT/

# Copy seed corpora if they exist
if [ -d "$SRC/rustledger/crates/rustledger-parser/fuzz/corpus/fuzz_parse" ]; then
    zip -j $OUT/fuzz_parse_seed_corpus.zip $SRC/rustledger/crates/rustledger-parser/fuzz/corpus/fuzz_parse/*
fi

if [ -d "$SRC/rustledger/crates/rustledger-parser/fuzz/corpus/fuzz_parse_line" ]; then
    zip -j $OUT/fuzz_parse_line_seed_corpus.zip $SRC/rustledger/crates/rustledger-parser/fuzz/corpus/fuzz_parse_line/*
fi

if [ -d "$SRC/rustledger/crates/rustledger-query/fuzz/corpus/fuzz_query_parse" ]; then
    zip -j $OUT/fuzz_query_parse_seed_corpus.zip $SRC/rustledger/crates/rustledger-query/fuzz/corpus/fuzz_query_parse/*
fi

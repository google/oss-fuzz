#!/bin/bash -eu
# Copyright 2025 Google LLC
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

export ASAN_OPTIONS=detect_leaks=0

# Build and install the compiler...
# Disable other languages to save on compile time
./bootstrap.sh
./configure --enable-static --disable-shared --with-cpp=no --with-c_glib=no --with-python=no --with-py3=no --with-go=no --with-rs=yes --with-java=no --with-nodejs=no --with-dotnet=no --with-kotlin=no
make -j$(nproc)

# Build rust fuzzers
pushd lib/rs/test/fuzz
# Don't do a make check so we don't fail clippy on formatting and stuff
make stubs
rust_target_out_dir=target/x86_64-unknown-linux-gnu/release
cargo fuzz build -O
cargo fuzz list | while read i; do
    cp $rust_target_out_dir/$i $OUT/fuzz_$i
done
popd

# Generate corpora
pushd lib/rs/test/fuzz
mkdir -p corpus/{binary,compact}

# Generate corpus files for each protocol type
echo "Generating binary protocol corpus..."
$rust_target_out_dir/corpus_generator --protocol binary --output-dir corpus/binary --generate 1024

echo "Generating compact protocol corpus..."
$rust_target_out_dir/corpus_generator --protocol compact --output-dir corpus/compact --generate 1024

# Create seed corpus zip files once per protocol
zip -q -j "$OUT/binary_protocol_corpus.zip" corpus/binary/*
zip -q -j "$OUT/compact_protocol_corpus.zip" corpus/compact/*

# Define fuzzer names for Rust-specific fuzzers
BINARY_FUZZERS="fuzz_parse_binary fuzz_roundtrip_binary"
COMPACT_FUZZERS="fuzz_parse_compact fuzz_roundtrip_compact"

# Copy the zip files for each fuzzer
for fuzzer in $BINARY_FUZZERS; do
    cp "$OUT/binary_protocol_corpus.zip" "$OUT/${fuzzer}_seed_corpus.zip"
done

for fuzzer in $COMPACT_FUZZERS; do
    cp "$OUT/compact_protocol_corpus.zip" "$OUT/${fuzzer}_seed_corpus.zip"
done

# Clean up temporary protocol corpus files
rm "$OUT/binary_protocol_corpus.zip" "$OUT/compact_protocol_corpus.zip"

popd
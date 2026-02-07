#!/bin/bash -eu
# Copyright 2025 Google Inc.
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

cd $SRC/rust-url

# Build all workspace-level fuzz targets
cd fuzz
cargo fuzz build -O

# Copy all fuzz targets to $OUT
for target in fuzz_url_parse_roundtrip fuzz_url_differential fuzz_url_setters fuzz_idna fuzz_data_url fuzz_form_urlencoded fuzz_percent_encoding; do
  cp target/x86_64-unknown-linux-gnu/release/$target $OUT/
done

# Copy seed corpus
if [ -d corpus/seed ]; then
  for target in fuzz_url_parse_roundtrip fuzz_url_differential fuzz_url_setters fuzz_idna fuzz_data_url fuzz_form_urlencoded fuzz_percent_encoding; do
    mkdir -p $OUT/${target}_seed_corpus
    cp corpus/seed/* $OUT/${target}_seed_corpus/
    cd $OUT && zip -j ${target}_seed_corpus.zip ${target}_seed_corpus/* && rm -rf ${target}_seed_corpus
    cd $SRC/rust-url/fuzz
  done
fi

# Copy dictionary
if [ -f fuzz.dict ]; then
  for target in fuzz_url_parse_roundtrip fuzz_url_differential fuzz_url_setters fuzz_idna fuzz_data_url fuzz_form_urlencoded fuzz_percent_encoding; do
    cp fuzz.dict $OUT/${target}.dict
  done
fi

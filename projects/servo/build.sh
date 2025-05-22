#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

cd $SRC/html5ever/html5ever/fuzz
cargo update -p serde --precise 1.0.200
cd ..
cargo fuzz build -O
cp fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_document_parse $OUT/

cd $SRC/html5ever/xml5ever/fuzz
cargo update -p serde --precise 1.0.200
cd ..
cargo fuzz build -O
cp fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_document_parse $OUT/

cd $SRC/rust-cssparser
cargo fuzz build -O
cp fuzz/target/x86_64-unknown-linux-gnu/release/cssparser $OUT/fuzz-cssparser

cd $SRC/rust-url/url
cargo fuzz build -O
cp fuzz/target/x86_64-unknown-linux-gnu/release/fuzz-url $OUT/fuzz-url
cp fuzz/target/x86_64-unknown-linux-gnu/release/parse $OUT/fuzz-url-parse

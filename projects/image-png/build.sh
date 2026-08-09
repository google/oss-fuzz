#!/bin/bash -eu
# Copyright 2021 Google LLC
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

cd $SRC
cd image-png
cargo fuzz build -O

cp fuzz/target/x86_64-unknown-linux-gnu/release/decode $OUT/
find . -type f -name "*.png" -exec zip -r -j "$OUT/decode_seed_corpus.zip" {} +

cp fuzz/target/x86_64-unknown-linux-gnu/release/buf_independent $OUT/
cp fuzz/target/x86_64-unknown-linux-gnu/release/roundtrip $OUT/


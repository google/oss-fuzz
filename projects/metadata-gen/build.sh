#!/bin/bash -eu
# Copyright 2024 - 2026 metadata-gen contributors
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
#
# OSS-Fuzz build: every cargo-fuzz target, with its committed seed
# corpus zipped beside it as <target>_seed_corpus.zip.
cd "$SRC/metadata-gen"
cargo fuzz build -O
release="fuzz/target/x86_64-unknown-linux-gnu/release"
for target in $(cargo fuzz list); do
  cp "$release/$target" "$OUT/"
  (cd "fuzz/corpus/$target" && zip -q -r "$OUT/${target}_seed_corpus.zip" .)
done

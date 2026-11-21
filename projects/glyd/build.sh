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

# Glyd's fuzz targets (fuzz/, cargo-fuzz: the parsers that read what a stranger sends: GGUF, safetensors, JSON, chat
# requests and templates, tool calls, grammars, HTTP heads, model configs and packed directories), each with its seeds.
cd $SRC/glyd/fuzz
cargo fuzz build -O
FUZZ_OUT=target/x86_64-unknown-linux-gnu/release
python3 seed.py
for t in $(cargo fuzz list); do
  cp "$FUZZ_OUT/$t" "$OUT/"
  if [ -d "corpus/$t" ] && [ -n "$(ls -A "corpus/$t")" ]; then
    (cd "corpus/$t" && zip -q -r "$OUT/${t}_seed_corpus.zip" .)
  fi
done

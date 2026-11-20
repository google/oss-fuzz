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

# Install runtime dependencies only. PostCSS's devDependencies pull in tools
# that have peer-dep conflicts and are unrelated to the library's runtime
# behavior, so we skip them.
npm install --omit=dev --ignore-scripts --legacy-peer-deps
npm install --save-dev --legacy-peer-deps @jazzer.js/core

# Build a seed corpus from the upstream postcss-parser-tests CSS cases so
# the fuzzer starts mutating from realistic, parser-shaped inputs rather
# than from empty bytes.
mkdir -p "$WORK/seed_corpus"
cp "$SRC"/postcss-parser-tests/cases/*.css "$WORK/seed_corpus/"
(cd "$WORK/seed_corpus" && zip -q -r "$OUT/fuzz_parse_seed_corpus.zip" .)

# Ship the CSS dictionary alongside the fuzzer so libFuzzer can splice in
# common CSS tokens during mutation. The dictionary lives in the upstream
# postcss repo under test/fuzzing/, so it is already present in the clone.
cp "$SRC/postcss/test/fuzzing/fuzz_parse.dict" "$OUT/fuzz_parse.dict"

# Build Fuzzers. The harness lives upstream at test/fuzzing/fuzz_parse.js
# and is supplied by the postcss clone above.
compile_javascript_fuzzer postcss test/fuzzing/fuzz_parse.js -i postcss --sync

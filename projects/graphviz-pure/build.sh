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

# Builds the cargo-fuzz targets of graphviz-pure (fuzz/ of the repository) and
# installs them in $OUT, each with its dictionary, its libFuzzer options and its
# seed corpus. The same targets are built for ClusterFuzzLite by
# .clusterfuzzlite/build.sh in the repository; keep the two in step.

cd "$SRC/graphviz-pure/fuzz"

# Each target links the whole port with thin LTO; ten links at once run out of
# memory in the builder.
export CARGO_BUILD_JOBS=2

# OSS-Fuzz exports RUSTFLAGS with -Zsanitizer=address, and cargo-fuzz appends
# the ambient RUSTFLAGS to its own flags, so the fuzzers are built with
# AddressSanitizer. --debug-assertions keeps the arithmetic overflow checks, so
# an overflow is a crash too.
cargo fuzz build -O --debug-assertions

# The seed corpora: the repository's test graphs. seed-corpus.py writes the DOT
# graphs for the parse and the render_* targets and the HTML labels for
# parse_html.
python3 -I seed-corpus.py "$WORK/seeds"
(cd "$WORK/seeds/dot" && zip -q -r "$WORK/dot_seed_corpus.zip" .)
(cd "$WORK/seeds/html" && zip -q -r "$WORK/html_seed_corpus.zip" .)

for src in fuzz_targets/*.rs; do
  name=$(basename "${src%.rs}")
  cp "target/x86_64-unknown-linux-gnu/release/$name" "$OUT/"
  cp dot.dict "$OUT/$name.dict"
  cp fuzz.options "$OUT/$name.options"
  if [ "$name" = parse_html ]; then
    cp "$WORK/html_seed_corpus.zip" "$OUT/${name}_seed_corpus.zip"
  else
    cp "$WORK/dot_seed_corpus.zip" "$OUT/${name}_seed_corpus.zip"
  fi
done

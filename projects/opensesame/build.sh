#!/usr/bin/env bash
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
# Build every cargo-fuzz target into $OUT for OSS-Fuzz / ClusterFuzzLite,
# with each committed seed corpus zipped beside it. The same shape runs
# locally via scripts/fuzz/fuzz-pr-gate.sh and scripts/fuzz/fuzz-batch.sh.
set -euo pipefail

PROJECT="${SRC:-/src}/opensesame"
cd "$PROJECT"

if ! command -v cargo-fuzz >/dev/null 2>&1; then
  cargo install cargo-fuzz --locked --version 0.13.2
fi

# cargo-fuzz's default sanitizer is address, which is what project.yaml
# declares; the flag is stated explicitly so a future sanitizer addition is a
# one-line change.
cargo +nightly fuzz build --release --sanitizer address --fuzz-dir tests/fuzz/cargo

OUT="${OUT:-$PROJECT/tests/fuzz/cargo/artifacts}"
mkdir -p "$OUT"

shopt -s nullglob
for bin in tests/fuzz/cargo/target/*/release/*; do
  name="$(basename "$bin")"
  case "$name" in
    *.d|*.rlib|*.so|*.a|incremental|deps|build|examples|native) continue ;;
  esac
  if [[ -x "$bin" && -f "$bin" ]]; then
    cp -f "$bin" "$OUT/$name"
    corpus="tests/fuzz/cargo/corpus/$name"
    if [[ -d "$corpus" ]]; then
      (cd "$corpus" && zip -qr "$OUT/${name}_seed_corpus.zip" .)
    fi
  fi
done

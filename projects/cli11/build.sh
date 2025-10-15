#!/bin/bash -eu
# Copyright 2025 Google LLC
# Licensed under the Apache License, Version 2.0
# See the License for the specific language governing permissions and
# limitations under the License.
set -o pipefail

# --- Build the upstream CLI11 fuzz harness ---
"$CXX" ${CXXFLAGS:-} -std=c++17 -I"$SRC/cli11/include" \
  "$SRC/cli11/fuzz/cli11_app_fuzz.cpp" "$SRC/cli11/fuzz/fuzzApp.cpp" \
  -o "$OUT/cli11_app_fuzzer" $LIB_FUZZING_ENGINE ${LDFLAGS:-}

# --- Package dictionary (if present) ---
if [[ -f "$SRC/cli11/fuzz/fuzz_dictionary1.txt" ]]; then
  cat "$SRC/cli11/fuzz/fuzz_dictionary1.txt" "$SRC/cli11/fuzz/fuzz_dictionary2.txt" \
    > "$OUT/cli11_app_fuzzer.dict" || true
fi

# --- Tiny, non-crashing seed corpus (zip + plain dir) ---
seeddir=/tmp/cli11_seeds
mkdir -p "$seeddir"
: > "$seeddir/empty"                 # zero-byte
printf -- '--help\n' > "$seeddir/help"

# 1) Flat zip (no directories) for libFuzzer/honggfuzz
zip -j -q "$OUT/cli11_app_fuzzer_seed_corpus.zip" "$seeddir/empty" "$seeddir/help"

# 2) Plain directory for AFL++ (some runners rely on a real dir)
rm -rf "$OUT/cli11_app_fuzzer_seed_corpus"
mkdir -p "$OUT/cli11_app_fuzzer_seed_corpus"
cp -f "$seeddir/empty" "$seeddir/help" "$OUT/cli11_app_fuzzer_seed_corpus/" || true

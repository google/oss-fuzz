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
set -o pipefail

# Build CLI11's upstream fuzzer (header-only library; compile harness directly)
"$CXX" ${CXXFLAGS:-} -std=c++17 -I"$SRC/cli11/include" \
  "$SRC/cli11/fuzz/cli11_app_fuzz.cpp" \
  "$SRC/cli11/fuzz/fuzzApp.cpp" \
  -o "$OUT/cli11_app_fuzzer" $LIB_FUZZING_ENGINE ${LDFLAGS:-}

# Ship libFuzzer dictionary if available (improves coverage)
if [ -f "$SRC/cli11/fuzz/fuzz_dictionary1.txt" ] || [ -f "$SRC/cli11/fuzz/fuzz_dictionary2.txt" ]; then
  cat "$SRC/cli11/fuzz"/fuzz_dictionary*.txt > "$OUT/cli11_app_fuzzer.dict" || true
fi

# Minimal seed corpus (maintainers can provide a richer corpus later)
mkdir -p /tmp/seed && printf -- '--help\n' > /tmp/seed/a
zip -rq "$OUT/cli11_app_fuzzer_seed_corpus.zip" /tmp/seed

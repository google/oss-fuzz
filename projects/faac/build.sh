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

# 1. Seed corpus. gen_corpus.py runs the faac CLI to make encoder-derived
#    seeds, so build it once without sanitizer or fuzzer flags.
(
  unset CFLAGS CXXFLAGS LDFLAGS
  meson setup build-seed -Ddefault_library=static
  ninja -C build-seed tests/fuzz/corpus.stamp
)

# 2. Instrumented harnesses. CFLAGS from OSS-Fuzz carry the sanitizer and
#    -fsanitize=fuzzer-no-link; the fuzzing-engine option links the engine.
meson setup build-fuzz \
  -Ddefault_library=static \
  -Db_lundef=false \
  -Db_lto=false \
  -Dfuzzing-engine="$LIB_FUZZING_ENGINE"
ninja -C build-fuzz

for f in build-fuzz/tests/fuzz/fuzz_*; do
  [ -f "$f" ] && [ -x "$f" ] || continue
  name=$(basename "$f")
  cp "$f" "$OUT/"
  case $name in
    fuzz_faac_encode|fuzz_faac_faad_pce) max_len=70000 ;;
    fuzz_faam_annexb) max_len=300000 ;;
    fuzz_frontend_wav) max_len=4096 ;;
    *) max_len=65536 ;;
  esac
  printf '[libfuzzer]\nmax_len = %s\n' "$max_len" > "$OUT/$name.options"
  seeds=build-seed/tests/fuzz/corpus/${name#fuzz_}
  if [ -d "$seeds" ] && [ -n "$(ls -A "$seeds")" ]; then
    (cd "$seeds" && zip -q -r "$OUT/${name}_seed_corpus.zip" .)
  fi
done

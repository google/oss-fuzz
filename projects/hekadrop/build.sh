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

if [ "$SANITIZER" = "coverage" ]; then
    export RUSTFLAGS="$RUSTFLAGS -C debug-assertions=no"
    export CFLAGS=""
fi

cd "$SRC/hekadrop"

cargo fuzz build -O --fuzz-dir fuzz

# Binary path: mimariye göre değişir (x86_64, i686, aarch64 vs.)
# `find` ile dinamik lokasyon — hardcoded triple yok.
for f in fuzz/fuzz_targets/*.rs; do
    target=$(basename "${f%.*}")
    bin=$(find fuzz/target -name "$target" -type f \
        ! -name "*.d" ! -path "*/deps/*" | head -1)
    if [ -n "$bin" ]; then
        cp "$bin" "$OUT/$target"
    fi
    if [ -d "fuzz/corpus/$target" ] && \
       [ -n "$(ls -A "fuzz/corpus/$target" 2>/dev/null)" ]; then
        zip -j "$OUT/${target}_seed_corpus.zip" "fuzz/corpus/$target"/*
    fi
done

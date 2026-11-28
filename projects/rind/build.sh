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

# OSS-Fuzz's build script for rind: every cargo-fuzz target, with the seed
# corpora sh/fuzz-seed.sh writes. This directory is what google/oss-fuzz's
# projects/rind copies; check it with that repo's `infra/helper.py check_build`.

cd "$SRC/rind"

# OSS-Fuzz's coverage build fails on debug assertions in std's
# instrumentation, as rustls's build notes.
if [ "$SANITIZER" = "coverage" ]; then
    export RUSTFLAGS="$RUSTFLAGS -C debug-assertions=no"
    export CFLAGS=""
fi

cargo fuzz build -O
sh/fuzz-seed.sh

for target in $(cargo fuzz list); do
    cp "target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"
    if [ -d "fuzz/corpus/$target" ]; then
        zip -qjr "$OUT/${target}_seed_corpus.zip" "fuzz/corpus/$target"
    fi
done

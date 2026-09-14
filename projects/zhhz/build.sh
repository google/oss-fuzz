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
# OSS-Fuzz build script for zhhz.
# Invoked by ClusterFuzz in the gcr.io/oss-fuzz-base/base-builder-rust
# image, with $SANITIZER set to one of address|memory|undefined.
#
# Outputs:
#   $OUT/zhhz-fuzz-fmm_segment         (libFuzzer binary)
#   $OUT/zhhz-fuzz-convert_roundtrip   (libFuzzer binary)
#   $OUT/zhhz-fuzz-fmm_segment_seed_corpus.zip
#   $OUT/zhhz-fuzz-convert_roundtrip_seed_corpus.zip
################################################################################

# The base-builder-rust image has pinned nightly Rust + cargo-fuzz pre-installed.

# Clone zhhz into the standard OSS-Fuzz source location.
git clone --depth 1 https://github.com/ljh-sh/zhhz.git "$SRC/zhhz"

# Compile each fuzz target with the requested sanitizer.
cd "$SRC/zhhz/fuzz"

for target in fmm_segment convert_roundtrip; do
    echo "Building $target with sanitizer=$SANITIZER"
    cargo +nightly fuzz build \
        --sanitizer="$SANITIZER" \
        --release \
        "$target"

    cp "target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"
done

# Bundle any committed seed corpus so ClusterFuzz can start with it.
for target in fmm_segment convert_roundtrip; do
    if [ -d "corpus/$target" ] && [ -n "$(ls -A corpus/$target 2>/dev/null)" ]; then
        cd "$SRC/zhhz/fuzz"
        zip -jqr "$OUT/${target}_seed_corpus.zip" "corpus/$target"
    fi
done

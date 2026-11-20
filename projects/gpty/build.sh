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

cd $SRC/gpty

# The pinned FFmpeg prefix the Dockerfile built. The media fuzzer loads these
# shared libraries at run time; they are copied into $OUT below.
source dist/ffmpeg/linux-x86_64/env.sh

# RUSTUP_TOOLCHAIN is set by the Dockerfile to the nightly gpty's CI uses;
# rust-toolchain.toml would otherwise select the stable pin.
cargo fuzz build -O --debug-assertions

FUZZ_TARGET_OUTPUT_DIR=fuzz/target/x86_64-unknown-linux-gnu/release
for f in fuzz/fuzz_targets/*.rs; do
  target="$(basename "${f%.rs}")"
  cp "$FUZZ_TARGET_OUTPUT_DIR/$target" "$OUT/"
  # The fuzzer finds libav* beside itself in the runner.
  patchelf --set-rpath '$ORIGIN/' "$OUT/$target"
  # Every target has handwritten seeds under fuzz/corpus/.
  if [ -n "$(find "fuzz/corpus/$target" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
    zip -j -q "$OUT/${target}_seed_corpus.zip" fuzz/corpus/"$target"/*
  fi
done

# The shared FFmpeg libraries the media fuzzer links. Only the soname files
# (libfoo.so.7, not the libfoo.so linker symlink or the libfoo.so.7.1.2 file):
# those are the DT_NEEDED names, and -L copies the real content.
find dist/ffmpeg/linux-x86_64/lib -name 'lib*.so.[0-9]*' -not -name 'lib*.so.*.*' \
  -exec cp -L {} "$OUT/" \;

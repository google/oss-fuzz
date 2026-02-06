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

# Handle coverage builds
if [ "$SANITIZER" = "coverage" ]; then
  export RUSTFLAGS="$RUSTFLAGS -C debug-assertions=no"
  export CFLAGS=""
fi

# Merge additional fuzz targets from OSS-Fuzz repo
cd $SRC/quinn
cp -r $SRC/quinn-fuzz/fuzz_targets/* fuzz/fuzz_targets/
cp $SRC/quinn-fuzz/Cargo.toml fuzz/Cargo.toml

# Build the fuzz targets
cargo fuzz build -O

# Copy fuzz targets to output directory
# cargo fuzz puts binaries in target/, not fuzz/target/
FUZZ_TARGET_OUTPUT_DIR=target/x86_64-unknown-linux-gnu/release
for f in fuzz/fuzz_targets/*.rs; do
  FUZZ_TARGET_NAME=$(basename ${f%.*})
  cp $FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME $OUT/
done

# Copy seed corpus
if [ -d $SRC/seeds ]; then
  for f in fuzz/fuzz_targets/*.rs; do
    FUZZ_TARGET=$(basename ${f%.*})
    zip -jr $OUT/${FUZZ_TARGET}_seed_corpus.zip $SRC/seeds/
  done
fi

# Copy dictionary file
cp $SRC/fuzz.dict $OUT/

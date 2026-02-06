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

# Build the fuzz targets
cd $SRC/toml
cargo fuzz build -O

# Copy fuzz targets to output directory
for f in $SRC/toml/fuzz/fuzz_targets/*.rs; do
  FUZZ_TARGET=$(basename ${f%.*})
  cp fuzz/target/x86_64-unknown-linux-gnu/release/${FUZZ_TARGET} $OUT/
done

# Copy seed corpus
for f in $SRC/toml/fuzz/fuzz_targets/*.rs; do
  FUZZ_TARGET=$(basename ${f%.*})
  zip -jr \
    $OUT/${FUZZ_TARGET}_seed_corpus.zip \
    $SRC/toml/fuzz/seeds/
done

# Copy dictionary file
cp $SRC/toml/fuzz.dict $OUT/

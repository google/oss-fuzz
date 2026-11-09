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
#
################################################################################

if [ "$SANITIZER" = "coverage" ]
then
  export RUSTFLAGS="$RUSTFLAGS -C debug-assertions=no"
  export CFLAGS=""
fi

cd $SRC/loom/fuzz

# Build all fuzz targets
cargo fuzz build -O

# Copy fuzz targets to output
for f in fuzz_targets/*.rs
do
  FUZZ_TARGET=$(basename ${f%.*})
  cp target/x86_64-unknown-linux-gnu/release/${FUZZ_TARGET} $OUT/

  # Copy seed corpus if available
  if [[ -d corpus/$FUZZ_TARGET/ ]]; then
    zip -jr $OUT/${FUZZ_TARGET}_seed_corpus.zip corpus/$FUZZ_TARGET/
  fi
done

# Copy dictionary
if [[ -f dictionaries/wasm.dict ]]; then
  for f in fuzz_targets/*.rs
  do
    FUZZ_TARGET=$(basename ${f%.*})
    cp dictionaries/wasm.dict $OUT/${FUZZ_TARGET}.dict
  done
fi

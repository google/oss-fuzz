#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

cd oak_functions/loader/

if [ "$SANITIZER" = "coverage" ]
then
  export RUSTFLAGS="$RUSTFLAGS -C debug-assertions=no"
  chmod +x $SRC/rustc.py
  export RUSTC="$SRC/rustc.py"
fi

cargo fuzz build --release

# Clear RUSTFLAGS, and build the fuzzable example. The Wasm module is stored in `/out/bin`.
# Keep this in sync with `https://github.com/project-oak/oak/blob/main/oak_functions/loader/fuzz/fuzz_targets/wasm_invoke.rs`.
export RUSTFLAGS=""
cargo  -Zunstable-options build \
  --target=wasm32-unknown-unknown \
  --target-dir=target/wasm32-unknown-unknown/wasm \
  --out-dir="$OUT/bin" \
  --manifest-path=../examples/fuzzable/module/Cargo.toml

FUZZ_TARGET_OUTPUT_DIR=fuzz/target/x86_64-unknown-linux-gnu/release
for f in fuzz/fuzz_targets/*.rs
do
    FUZZ_TARGET_NAME=$(basename ${f%.*})
    cp $FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME $OUT/
done

# Check that the Wams file is in the correct location.
readonly FILE="$OUT/bin/fuzzable.wasm"
if [ ! -f "$FILE" ]; then
  exit 1
fi


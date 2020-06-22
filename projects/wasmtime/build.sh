#!/bin/bash -eu
# Copyright 2020 Google Inc.
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

# Note: This project creates Rust fuzz targets exclusively
PROJECT_DIR=$SRC/wasmtime

# Build with all features to enable the binaryen-using fuzz targets, and
# the peepmatic fuzz targets.
cd $PROJECT_DIR/fuzz && cargo fuzz build -O --debug-assertions --all-features

FUZZ_TARGET_OUTPUT_DIR=$PROJECT_DIR/target/x86_64-unknown-linux-gnu/release
for f in $SRC/wasmtime/fuzz/fuzz_targets/*.rs
do
    FUZZ_TARGET_NAME=$(basename ${f%.*})
    cp $FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME $OUT/
    zip -jr $OUT/${FUZZ_TARGET_NAME}_seed_corpus.zip $PROJECT_DIR/wasmtime-libfuzzer-corpus/$FUZZ_TARGET_NAME/
    cp $SRC/default.options $OUT/$FUZZ_TARGET_NAME.options
done

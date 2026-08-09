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
PROJECT_DIR=$SRC/mp4parse-rust
cd $PROJECT_DIR/mp4parse_capi/fuzz && cargo fuzz build -O --debug-assertions

# collect avif files
mkdir $PROJECT_DIR/avif_corpus
find $PROJECT_DIR/mp4parse -type f -name '*.avif' -exec cp '{}' $PROJECT_DIR/avif_corpus \;

# collect mp4 files
mkdir $PROJECT_DIR/mp4_corpus
find $PROJECT_DIR/mp4parse/tests -type f -name '*.mp4' -exec cp '{}' $PROJECT_DIR/mp4_corpus \;
find $PROJECT_DIR/mp4parse_capi/tests/ -type f -name '*.mp4' -exec cp '{}' $PROJECT_DIR/mp4_corpus \;

FUZZ_TARGET_OUTPUT_DIR=$PROJECT_DIR/mp4parse_capi/fuzz/target/x86_64-unknown-linux-gnu/release
for f in $SRC/mp4parse-rust/mp4parse_capi/fuzz/fuzz_targets/*.rs
do
    FUZZ_TARGET_NAME=$(basename ${f%.*})
    cp $FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME $OUT/
    cp $PROJECT_DIR/mp4parse_capi/fuzz/mp4.dict $OUT/$FUZZ_TARGET_NAME.dict
    cp $SRC/default.options $OUT/$FUZZ_TARGET_NAME.options
    zip -jr $OUT/${FUZZ_TARGET_NAME}_seed_corpus.zip $PROJECT_DIR/${FUZZ_TARGET_NAME}_corpus/
done

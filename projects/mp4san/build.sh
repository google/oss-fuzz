#!/bin/bash -eu
# Copyright 2023 Google LLC
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

PROJECT_DIR=$SRC/mp4san

for crate_dir in mp4san webpsan; do
    FUZZ_DIR=$PROJECT_DIR/$crate_dir/fuzz
    cd $FUZZ_DIR && cargo fuzz build -O --debug-assertions

    FUZZ_INPUT_DIR=$FUZZ_DIR/input

    FUZZ_TARGET_OUTPUT_DIR=$FUZZ_DIR/target/x86_64-unknown-linux-gnu/release/
    for fuzz_target in $FUZZ_DIR/fuzz_targets/*.rs
    do
        FUZZ_TARGET_NAME=$(basename ${fuzz_target%.*})
        OUT_FUZZ_TARGET_NAME=$crate_dir-$FUZZ_TARGET_NAME
        cp $FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME $OUT/$OUT_FUZZ_TARGET_NAME
        cat $FUZZ_DIR/*.dict > $OUT/$OUT_FUZZ_TARGET_NAME.dict
        zip -jr $OUT/${OUT_FUZZ_TARGET_NAME}_seed_corpus.zip $FUZZ_INPUT_DIR/
    done
done

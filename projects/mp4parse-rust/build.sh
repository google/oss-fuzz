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

export CUSTOM_LIBFUZZER_PATH="$LIB_FUZZING_ENGINE_DEPRECATED"
export CUSTOM_LIBFUZZER_STD_CXX=c++
PROJECT_DIR=$SRC/mp4parse-rust

# Because Rust does not support sanitizers via CFLAGS/CXXFLAGS, the environment
# variables are overridden with values from base-images/base-clang only

export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
export CXXFLAGS_EXTRA="-stdlib=libc++"
export CXXFLAGS="$CFLAGS $CXXFLAGS_EXTRA"
export RUSTFLAGS="-Cdebuginfo=1 -Cforce-frame-pointers"

cd $PROJECT_DIR/mp4parse_capi/fuzz && cargo fuzz build -O --debug-assertions

mkdir $PROJECT_DIR/corpus
cp $PROJECT_DIR/mp4parse/tests/*.mp4  $PROJECT_DIR/corpus
cp $PROJECT_DIR/mp4parse_capi/tests/*.mp4 $PROJECT_DIR/corpus

FUZZ_TARGET_OUTPUT_DIR=$PROJECT_DIR/mp4parse_capi/fuzz/target/x86_64-unknown-linux-gnu/release
for f in $SRC/mp4parse-rust/mp4parse_capi/fuzz/fuzz_targets/*.rs
do
    FUZZ_TARGET_NAME=$(basename ${f%.*})
    cp $FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME $OUT/
    cp $PROJECT_DIR/mp4parse_capi/fuzz/mp4.dict $OUT/$FUZZ_TARGET_NAME.dict
    zip -jr $OUT/${FUZZ_TARGET_NAME}_seed_corpus.zip $PROJECT_DIR/corpus/
done

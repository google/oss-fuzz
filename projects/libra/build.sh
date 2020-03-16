#!/bin/bash -eux
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

# make OSS-Fuzz work with Rust
export CUSTOM_LIBFUZZER_PATH="$LIB_FUZZING_ENGINE_DEPRECATED"
export CUSTOM_LIBFUZZER_STD_CXX=c++
export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
export CXXFLAGS_EXTRA="-stdlib=libc++"
export CXXFLAGS="$CFLAGS $CXXFLAGS_EXTRA"

# RUSTC_BOOTSTRAP: to get some nightly features like ASAN
export RUSTC_BOOTSTRAP=1 

#
cd $SRC/libra/testsuite/libra-fuzzer

# list fuzzers
cargo run --bin libra-fuzzer list --no-desc > fuzzer_list

# build corpus and move to $OUT
cat fuzzer_list | while read -r line
do
    cargo run --bin libra-fuzzer generate -n 128 $line
    zip -r $OUT/"$line"_seed_corpus.zip fuzz/corpus/$line
    rm -r fuzz/corpus/$line
done

# build fuzzers
# --cfg fuzzing      -> used to change code logic
# -Cdebug-assertions -> to get debug_assert in rust
# other flags        -> taken from cargo fuzz
export RUSTFLAGS="--cfg fuzzing -Cdebug-assertions -Cpasses=sancov -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-trace-compares -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-trace-geps -Cllvm-args=-sanitizer-coverage-prune-blocks=0 -Cllvm-args=-sanitizer-coverage-pc-table -Clink-dead-code -Cllvm-args=-sanitizer-coverage-stack-depth -Zsanitizer=address -Ccodegen-units=1"
cat fuzzer_list | while read -r line
do
    # build
    export SINGLE_FUZZ_TARGET="$line"
    cargo build --manifest-path fuzz/Cargo.toml --bin fuzzer_builder --release --target x86_64-unknown-linux-gnu
    # move fuzzer to $OUT
    mv $SRC/libra/target/x86_64-unknown-linux-gnu/release/fuzzer_builder $OUT/$SINGLE_FUZZ_TARGET
done

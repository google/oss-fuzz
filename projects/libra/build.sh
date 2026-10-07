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

# recipe:
# -------
# 1. we list all the fuzzers and save to a file fuzzer_list
# 2. we build the corpus for each fuzzer
# 3. we build all the fuzzers

# reset flags of OSS-Fuzz
export CFLAGS="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
export CXXFLAGS_EXTRA="-stdlib=libc++"
export CXXFLAGS="$CFLAGS $CXXFLAGS_EXTRA"

# correct workdir
cd $SRC/libra/testsuite/libra-fuzzer

# fetch all dependencies (needed for patching rocksdb)
cargo fetch

# patch rocksdb to not link libc++ statically
sed -i "s/link_cpp(&mut build)/build.cpp_link_stdlib(None)/" \
    /rust/git/checkouts/rust-rocksdb-a9a28e74c6ead8ef/72e45c3/librocksdb_sys/build.rs
# so now we need to link libc++ at the end
export RUSTFLAGS="-C link-arg=-L/usr/local/lib -C link-arg=-lc++"

# 1. list fuzzers
cargo run --bin libra-fuzzer list --no-desc > fuzzer_list

# 2. build corpus and move to $OUT
cat fuzzer_list | while read -r line
do
    cargo run --bin libra-fuzzer generate -n 128 $line
    zip -r $OUT/"$line"_seed_corpus.zip fuzz/corpus/$line
    rm -r fuzz/corpus/$line
done

# rust libfuzzer flags (https://github.com/rust-fuzz/libfuzzer/blob/master/build.rs#L12)
export CUSTOM_LIBFUZZER_PATH="$LIB_FUZZING_ENGINE_DEPRECATED"
export CUSTOM_LIBFUZZER_STD_CXX=c++
# export CUSTOM_LIBFUZZER_STD_CXX=none 

# export fuzzing flags
RUSTFLAGS="$RUSTFLAGS --cfg fuzzing"          # used to change code logic
RUSTFLAGS="$RUSTFLAGS -Cdebug-assertions"     # to get debug_assert in rust
RUSTFLAGS="$RUSTFLAGS -Zsanitizer=address"    # address sanitizer (ASAN)

RUSTFLAGS="$RUSTFLAGS -Cdebuginfo=1"         
RUSTFLAGS="$RUSTFLAGS -Cforce-frame-pointers"

RUSTFLAGS="$RUSTFLAGS -Cpasses=sancov"
RUSTFLAGS="$RUSTFLAGS -Cllvm-args=-sanitizer-coverage-level=4"
RUSTFLAGS="$RUSTFLAGS -Cllvm-args=-sanitizer-coverage-trace-compares"
RUSTFLAGS="$RUSTFLAGS -Cllvm-args=-sanitizer-coverage-inline-8bit-counters"
RUSTFLAGS="$RUSTFLAGS -Cllvm-args=-sanitizer-coverage-trace-geps"
RUSTFLAGS="$RUSTFLAGS -Cllvm-args=-sanitizer-coverage-prune-blocks=0"
RUSTFLAGS="$RUSTFLAGS -Cllvm-args=-sanitizer-coverage-pc-table"
RUSTFLAGS="$RUSTFLAGS -Clink-dead-code"
RUSTFLAGS="$RUSTFLAGS -Cllvm-args=-sanitizer-coverage-stack-depth"
RUSTFLAGS="$RUSTFLAGS -Ccodegen-units=1"

export RUSTFLAGS

# 3. build all the fuzzers!
cat fuzzer_list | while read -r line
do
    # build
    export SINGLE_FUZZ_TARGET="$line"
    cargo build --manifest-path fuzz/Cargo.toml --bin fuzzer_builder --release --target x86_64-unknown-linux-gnu
    # move fuzzer to $OUT
    mv $SRC/libra/target/x86_64-unknown-linux-gnu/release/fuzzer_builder $OUT/$SINGLE_FUZZ_TARGET
done

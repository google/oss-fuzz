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

# Commands migrated from Dockerfile to make CIFuzz work
# REF: https://github.com/google/oss-fuzz/issues/6755
git submodule update --init --recursive
git clone --depth 1 https://github.com/bytecodealliance/wasmtime-libfuzzer-corpus wasmtime-libfuzzer-corpus


# Note: This project creates Rust fuzz targets exclusively

build() {
  project=$1
  shift
  fuzzer_prefix=$1
  shift
  fuzz_targets=$1
  shift
  PROJECT_DIR=$SRC/$project

  # ensure we get absolute paths for the coverage report
  cd $PROJECT_DIR
  crate_src_abspath=`cargo metadata --no-deps --format-version 1 | jq -r '.workspace_root'`
  while read i; do
    export RUSTFLAGS="$RUSTFLAGS --remap-path-prefix $i=$crate_src_abspath/$i"
  done <<< "$(find . -name "*.rs" | cut -d/ -f2 | uniq)"

  cd $PROJECT_DIR/fuzz && cargo fuzz build --strip-dead-code -O --debug-assertions "$@"

  FUZZ_TARGET_OUTPUT_DIR=$PROJECT_DIR/target/x86_64-unknown-linux-gnu/release

  if [ "x$fuzz_targets" = "x" ]; then
      fuzz_targets=$PROJECT_DIR/fuzz/fuzz_targets/*.rs
  fi

  for f in $fuzz_targets; do
      src_name=$(basename ${f%.*})
      dst_name=$fuzzer_prefix$src_name
      cp $FUZZ_TARGET_OUTPUT_DIR/$src_name $OUT/$dst_name

      if [[ -d $SRC/wasmtime/wasmtime-libfuzzer-corpus/$dst_name/ ]]; then
          zip -jr \
              $OUT/${dst_name}_seed_corpus.zip \
              $SRC/wasmtime/wasmtime-libfuzzer-corpus/$dst_name/
      fi

      cp $SRC/default.options $OUT/$dst_name.options
  done
}

# Ensure OCaml environment is set up prior to Wasmtime build.
eval $(opam env)

build wasmtime "" ""
build wasm-tools wasm-tools- ""
build regalloc.rs regalloc- bt bt

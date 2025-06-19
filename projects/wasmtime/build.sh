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

# Note: This project creates Rust fuzz targets exclusively

build() {
  project=$1
  shift
  fuzzer_prefix=$1
  shift
  fuzz_targets=$1
  shift
  fuzz_target_path=$1
  shift
  PROJECT_DIR=$SRC/$project

  # ensure we get absolute paths for the coverage report
  cd $PROJECT_DIR
  crate_src_abspath=`cargo metadata --no-deps --format-version 1 | jq -r '.workspace_root'`
  while read i; do
    export RUSTFLAGS="$RUSTFLAGS --remap-path-prefix $i=$crate_src_abspath/$i"
  done <<< "$(find . -name "*.rs" | cut -d/ -f2 | uniq)"

  cd $PROJECT_DIR/fuzz && cargo fuzz build --sanitizer none --strip-dead-code -O --debug-assertions "$@"

  FUZZ_TARGET_OUTPUT_DIR=$PROJECT_DIR/$fuzz_target_path/x86_64-unknown-linux-gnu/release

  if [ "x$fuzz_targets" = "x" ]; then
      fuzz_targets=$PROJECT_DIR/fuzz/fuzz_targets/*.rs
  fi

  for f in $fuzz_targets; do
      src_name=$(basename ${f%.*})
      dst_name=$fuzzer_prefix$src_name
      cp $FUZZ_TARGET_OUTPUT_DIR/$src_name $OUT/$dst_name

      if [[ -f $SRC/$dst_name.options ]]; then
        cp $SRC/$dst_name.options $OUT/$dst_name.options
      else
        cp $SRC/default.options $OUT/$dst_name.options
      fi
  done
}

# Ensure OCaml environment is set up prior to Wasmtime build.
eval $(opam env)

build wasmtime "" "" target
build wasm-tools wasm-tools- "" target --features wasmtime
build regalloc2 regalloc2- ion_checker fuzz/target

# In coverage builds copy the opam header files into the output so coverage can
# find the source files.
if [ "$SANITIZER" = "coverage" ]; then
  cp --recursive --dereference --no-preserve mode,ownership --parents \
    $HOME/.opam/4.11.2/lib/ocaml $OUT
fi

#!/bin/bash -eu
# Copyright 2021 Google LLC
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

FUZZ_TARGET_OUTPUT_DIR=fuzz/target/x86_64-unknown-linux-gnu/release

# do not use override toolchain
# cf https://rust-lang.github.io/rustup/overrides.html
export RUSTUP_TOOLCHAIN=nightly-2021-11-01

build_and_copy() {
  pushd "$1"
  cargo fuzz build --release --debug-assertions
  for f in fuzz/fuzz_targets/*.rs
  do
    cp ${FUZZ_TARGET_OUTPUT_DIR}/$(basename ${f%.*}) $OUT/
  done
  popd
}

cd OpenSK

# Main OpenSK fuzzing targets
build_and_copy "."

# persistent storage library
build_and_copy libraries/persistent_store

# CBOR crate
build_and_copy libraries/cbor


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
#
################################################################################

cd crosvm

# Build crosvm fuzzers
# Unset the SRC variable as it will interfere with minijail's common.mk framework.
env -u SRC cargo +nightly \
    fuzz build \
    -O \
    --fuzz-dir=crosvm-fuzz \
    --features upstream-fuzz

# Copy fuzzer binaries to $OUT
FUZZ_TARGET_OUTPUT_DIR="target/x86_64-unknown-linux-gnu/release"
for f in crosvm-fuzz/*.rs; do
    FUZZ_TARGET_NAME=$(basename ${f%.*})
    cp "${FUZZ_TARGET_OUTPUT_DIR}/crosvm_${FUZZ_TARGET_NAME}" "$OUT/"
done

#!/bin/bash -eu
# Copyright 2024 Google LLC
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

cd $SRC/mdbook-i18n-helpers

fuzzer_list=$(cargo fuzz list)

# Validate fuzzers exist in the project
if [[ -z "$fuzzer_list" ]]; then
    echo "No fuzzers found"
    exit 1
fi

# Build fuzzers
cargo fuzz build -O --debug-assertions

FUZZ_TARGET_OUTPUT_DIR=target/x86_64-unknown-linux-gnu/release
while IFS= read -r fuzzer; do
  cp "$FUZZ_TARGET_OUTPUT_DIR/$fuzzer" $OUT/
done <<< "$fuzzer_list"

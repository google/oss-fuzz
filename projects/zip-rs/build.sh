#!/bin/bash -eu
# Copyright 2022 Google LLC
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

cd $SRC/zip

mkdir -vp fuzz-read-out
cargo afl build --manifest-path=fuzz/Cargo.toml --all-features -p fuzz_read
# Curated input corpus:
cargo afl fuzz -i fuzz/read/in -o fuzz-read-out fuzz/target/debug/fuzz_read
# Test data files:
cargo afl fuzz -i tests/data -e zip -o fuzz-read-out fuzz/target/debug/fuzz_read

mkdir -vp fuzz-write-out
cargo afl build --manifest-path=fuzz/Cargo.toml --all-features -p fuzz_write
# Curated input corpus and dictionary schema:
cargo afl fuzz -x fuzz/write/fuzz.dict -i fuzz/write/in -o fuzz-write-out fuzz/target/debug/fuzz_write


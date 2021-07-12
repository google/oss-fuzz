#!/bin/bash
# Copyright 2021 Google Inc.
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

set -eux

# https://google.github.io/oss-fuzz/getting-started/new-project-guide/#buildsh
OUT=${OUT:-out}
mkdir -p "$OUT"

build_type=${1:-"release"}
build_args="--release"
if [[ "$build_type" =~ "dev" ]]; then
    build_type="debug"
    build_args="--dev"
fi

cp -r "$SRC/fuzz" fuzz
cargo fuzz build $build_args --debug-assertions --verbose
cp "fuzz/target/x86_64-unknown-linux-gnu/$build_type/fuzz_pulldown_cmark_read" $OUT/

git clone --depth 1 https://github.com/michelf/mdtest
zip -r $OUT/fuzz_pulldown_cmark_read_seed_corpus.zip mdtest

git clone --depth 1 https://github.com/commonmark/cmark
cp cmark/test/fuzzing_dictionary $OUT/fuzz_pulldown_cmark_read.dict

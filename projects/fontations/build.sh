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

# To test:
#   export SRC=/tmp
#   export OUT=/tmp
#   git clone --depth 1 https://github.com/googlefonts/fontations /tmp/fontations
#   rm -rf /tmp/{font_srcs,corpus_tmp}
#   projects/fontations/build.sh

CLONE_TMP="$SRC/font_srcs"
CORPUS_TMP="$SRC/corpus_tmp"
mkdir "$CLONE_TMP"
mkdir "$CORPUS_TMP"

pushd "$CLONE_TMP"
git clone --depth 1 https://github.com/unicode-org/text-rendering-tests.git
git clone --depth 1 https://github.com/googlefonts/color-fonts.git
git clone --depth 1 https://github.com/harfbuzz/harfbuzz.git
for d in text-rendering-tests/fonts color-fonts/fonts harfbuzz/test; do
    find $d -name '*.[ot]t[fc]' -execdir cp {} ${CORPUS_TMP} \;
done
popd

pushd "$CORPUS_TMP"
zip seed_corpus.zip *
popd

cd $SRC/fontations
# Add +nightly after cargo if running locally and getting: error: the option `Z` is only accepted on the nightly compiler
cargo fuzz build -O --debug-assertions

# Based on zip-rs
RELEASE_DIR=target/x86_64-unknown-linux-gnu/release
num_fuzzers=0
for fuzzer in $(find $RELEASE_DIR -maxdepth 1 -type f -executable -name 'fuzz_*'  -exec basename {} \;); do
    cp -v "$CORPUS_TMP/seed_corpus.zip" $(basename $fuzzer)_seed_corpus.zip
    cp -v "$RELEASE_DIR/$fuzzer" $OUT/
    num_fuzzers=$((num_fuzzers+1))
done

# If we found 0 fuzzers something is very wrong
[[ "$num_fuzzers" -gt 0 ]] || { echo "No fuzzers!"; exit 1; }
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

# Install dependencies.
npm install --ignore-scripts --no-save emnapi
npm install
npm install --save-dev @jazzer.js/core

# Build Fuzzers.
compile_javascript_fuzzer sharp fuzz.js -i sharp

# Merge the seed corpus in a single directory, exclude files larger than 4k
mkdir -p fuzz/corpus
find \
  $SRC/afl-testcases/{gif*,jpeg*,png,tiff,webp}/full/images \
  test/fixtures \
  -type f -size -4k \
  -exec bash -c 'hash=($(sha1sum {})); mv {} fuzz/corpus/$hash' \;
zip -jrq $OUT/fuzz_seed_corpus.zip fuzz/corpus

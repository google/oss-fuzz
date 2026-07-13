#!/bin/bash -eu
# Copyright 2026 Google LLC
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

cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$CC" \
    -DCLUSTERFUZZ=ON

cmake --build build --target test_libfuzzer -j$(nproc)

cp build/regress/parser-libfuzzer/test_libfuzzer $OUT/
cp regress/parser-libfuzzer/test_libfuzzer.dict $OUT/
cp regress/parser-libfuzzer/test_libfuzzer.options $OUT/

# Seed corpus: local corpus + upstream fuzzing corpus
zip -rj $OUT/test_libfuzzer_seed_corpus.zip \
    regress/parser-libfuzzer/corpus/ \
    $SRC/openiked-fuzzing/corpus/test_libfuzzer/

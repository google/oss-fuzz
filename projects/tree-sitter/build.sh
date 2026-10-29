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

# Build tree-sitter C library (static, amalgamated)
cd $SRC/tree-sitter
$CC $CFLAGS -DTREE_SITTER_HIDE_SYMBOLS \
    -Ilib/include -Ilib/src \
    -c lib/src/lib.c -o lib.o

# Build tree-sitter-json grammar
cd $SRC/tree-sitter-json
$CC $CFLAGS \
    -I$SRC/tree-sitter/lib/include \
    -c src/parser.c -o parser.o

# Build and link the fuzzer
$CC $CFLAGS \
    -I$SRC/tree-sitter/lib/include \
    -c $SRC/parse_fuzzer.c -o parse_fuzzer.o

$CXX $CXXFLAGS \
    parse_fuzzer.o \
    $SRC/tree-sitter/lib.o \
    $SRC/tree-sitter-json/parser.o \
    $LIB_FUZZING_ENGINE \
    -o $OUT/parse_fuzzer

# Create a minimal seed corpus
mkdir -p $SRC/seed_corpus
echo -n '{}' > $SRC/seed_corpus/empty_object.json
echo -n '[]' > $SRC/seed_corpus/empty_array.json
echo -n '{"key": "value"}' > $SRC/seed_corpus/simple_object.json
echo -n '[1, 2, 3]' > $SRC/seed_corpus/simple_array.json
echo -n '{"a": [1, true, null, "str"]}' > $SRC/seed_corpus/mixed.json
echo -n 'not json at all {{{' > $SRC/seed_corpus/invalid.json
echo -n '{"nested": {"a": {"b": [1, {"c": 2}]}}}' > $SRC/seed_corpus/nested.json

cd $SRC/seed_corpus
zip -j $OUT/parse_fuzzer_seed_corpus.zip *

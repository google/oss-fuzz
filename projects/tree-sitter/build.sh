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

# Build tree-sitter as a static library
cd $SRC/tree-sitter

TS_CFLAGS="-std=c11 -fPIC -Ilib/include -Ilib/src -D_DEFAULT_SOURCE"

# Compile tree-sitter source files (non-amalgamated for better coverage)
for src_file in lib/src/*.c; do
    # Skip the amalgamated lib.c to avoid duplicate symbols
    if [ "$(basename "$src_file")" = "lib.c" ]; then
        continue
    fi
    $CC $CFLAGS $TS_CFLAGS -c "$src_file" -o "${src_file%.c}.o"
done

ar rcs libtree-sitter.a lib/src/*.o

# Build tree-sitter-json language
cd $SRC/tree-sitter-json
$CC $CFLAGS -std=c11 -fPIC \
    -I$SRC/tree-sitter/lib/include \
    -c src/parser.c -o parser_json.o
ar rcs libtree-sitter-json.a parser_json.o

# Build tree-sitter-html language
cd $SRC/tree-sitter-html
$CC $CFLAGS -std=c11 -fPIC \
    -I$SRC/tree-sitter/lib/include \
    -c src/parser.c -o parser_html.o

# html has a scanner.c for external tokens
if [ -f src/scanner.c ]; then
    $CC $CFLAGS -std=c11 -fPIC \
        -I$SRC/tree-sitter/lib/include \
        -Isrc \
        -c src/scanner.c -o scanner_html.o
    ar rcs libtree-sitter-html.a parser_html.o scanner_html.o
else
    ar rcs libtree-sitter-html.a parser_html.o
fi

# Build tree-sitter-javascript language
cd $SRC/tree-sitter-javascript
$CC $CFLAGS -std=c11 -fPIC \
    -I$SRC/tree-sitter/lib/include \
    -c src/parser.c -o parser_js.o

# javascript has a scanner.c for external tokens
if [ -f src/scanner.c ]; then
    $CC $CFLAGS -std=c11 -fPIC \
        -I$SRC/tree-sitter/lib/include \
        -Isrc \
        -c src/scanner.c -o scanner_js.o
    ar rcs libtree-sitter-javascript.a parser_js.o scanner_js.o
else
    ar rcs libtree-sitter-javascript.a parser_js.o
fi

# Common link flags
LINK_LIBS="$SRC/tree-sitter/libtree-sitter.a \
    $SRC/tree-sitter-json/libtree-sitter-json.a \
    $SRC/tree-sitter-html/libtree-sitter-html.a \
    $SRC/tree-sitter-javascript/libtree-sitter-javascript.a"

INCLUDE_FLAGS="-I$SRC/tree-sitter/lib/include"

# Build fuzz_ts_parser — parse arbitrary input with multiple grammars
$CC $CFLAGS $INCLUDE_FLAGS \
    -c $SRC/fuzz_ts_parser.c -o $SRC/fuzz_ts_parser.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    $SRC/fuzz_ts_parser.o $LINK_LIBS \
    -o $OUT/fuzz_ts_parser

# Build fuzz_ts_query — fuzz the S-expression query language
$CC $CFLAGS $INCLUDE_FLAGS \
    -c $SRC/fuzz_ts_query.c -o $SRC/fuzz_ts_query.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    $SRC/fuzz_ts_query.o $LINK_LIBS \
    -o $OUT/fuzz_ts_query

# Build fuzz_ts_subtree — fuzz tree traversal and editing operations
$CC $CFLAGS $INCLUDE_FLAGS \
    -c $SRC/fuzz_ts_subtree.c -o $SRC/fuzz_ts_subtree.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    $SRC/fuzz_ts_subtree.o $LINK_LIBS \
    -o $OUT/fuzz_ts_subtree

# Copy dictionaries
cp $SRC/fuzz_ts_parser.dict $OUT/
cp $SRC/fuzz_ts_query.dict $OUT/
cp $SRC/fuzz_ts_subtree.dict $OUT/

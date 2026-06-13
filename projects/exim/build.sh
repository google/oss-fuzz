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


cd "$SRC/exim/src"

# Build Exim as a library for fuzzing
cp src/EDITME Local/Makefile 2>/dev/null || cp EDITME Local/Makefile 2>/dev/null || true

# Compile Exim core parsing functions as a shared object
$CC $CFLAGS -I src -DCOMPILE_UTILITY \
    -c src/parse.c -o parse.o 2>/dev/null || \
$CC $CFLAGS -c src/parse.c -o parse.o

$CC $CFLAGS \
    -c "$SRC/fuzz_smtp_input.c" -o fuzz_smtp_input.o

$CC $CFLAGS $LIB_FUZZING_ENGINE \
    fuzz_smtp_input.o parse.o \
    -o "$OUT/fuzz_smtp_input"

# Simple seed corpus
mkdir -p seed_corpus
echo "user@example.com" > seed_corpus/simple.txt
echo '"quoted local"@example.com' > seed_corpus/quoted.txt
echo "user+tag@sub.domain.org" > seed_corpus/tag.txt
zip -j "$OUT/fuzz_smtp_input_seed_corpus.zip" seed_corpus/*

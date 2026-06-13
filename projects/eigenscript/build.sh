#!/bin/bash -eu
# Copyright 2026 Inaugural Systems
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

# OSS-Fuzz build script for EigenScript.
#
# OSS-Fuzz provides $CC, $CFLAGS, $LIB_FUZZING_ENGINE — we just thread
# those through. The fuzzer source lives at fuzz/fuzz_eigenscript.c and
# runs the same tokenize -> parse -> compile -> vm_execute pipeline
# main.c does.

# Files that make up the runtime, excluding main.c and the optional
# extensions. Keep this in sync with FUZZ_SOURCES in the project's
# Makefile if it ever drifts.
RUNTIME_SOURCES=(
    src/eigenscript.c
    src/lexer.c
    src/parser.c
    src/builtins.c
    src/builtins_tensor.c
    src/hash.c
    src/arena.c
    src/strbuf.c
    src/ext_store.c
    src/fmt.c
    src/lint.c
    src/chunk.c
    src/compiler.c
    src/vm.c
    src/jit.c
    src/trace.c
)

$CC $CFLAGS \
    -DEIGENSCRIPT_EXT_HTTP=0 \
    -DEIGENSCRIPT_EXT_MODEL=0 \
    -DEIGENSCRIPT_EXT_DB=0 \
    -DEIGENSCRIPT_VERSION='"oss-fuzz"' \
    -c fuzz/fuzz_eigenscript.c -o fuzz_eigenscript.o

OBJS=()
for src in "${RUNTIME_SOURCES[@]}"; do
    obj="$(basename "$src" .c).o"
    $CC $CFLAGS \
        -DEIGENSCRIPT_EXT_HTTP=0 \
        -DEIGENSCRIPT_EXT_MODEL=0 \
        -DEIGENSCRIPT_EXT_DB=0 \
        -DEIGENSCRIPT_VERSION='"oss-fuzz"' \
        -c "$src" -o "$obj"
    OBJS+=("$obj")
done

$CC $CFLAGS $LIB_FUZZING_ENGINE \
    fuzz_eigenscript.o "${OBJS[@]}" \
    -lm -lpthread \
    -o $OUT/fuzz_eigenscript

# Seed corpus: zip up the existing corpus dir. OSS-Fuzz uses
# <fuzzer_name>_seed_corpus.zip alongside the binary.
zip -j $OUT/fuzz_eigenscript_seed_corpus.zip fuzz/corpus/*

# Dictionary for keywords + punctuation — speeds up coverage growth
# on a grammared input like a programming language.
cp fuzz/eigenscript.dict $OUT/fuzz_eigenscript.dict

#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# build project
cd c++
autoreconf -i
./configure --disable-shared
make -j$(nproc)
make -j$(nproc) capnp-llvm-fuzzer-testcase
cp *fuzzer* $OUT/

# Build extra harnesses for code paths the default
# capnp-llvm-fuzzer-testcase does not exercise.
EXTRA_LIBS="libcapnp-test.a \
            .libs/libcapnpc.a \
            .libs/libcapnp-json.a \
            .libs/libcapnp-rpc.a \
            .libs/libcapnp.a \
            .libs/libkj-async.a \
            .libs/libkj.a"

for harness in "$SRC"/capnp-packed-fuzzer.c++ \
               "$SRC"/capnp-json-fuzzer.c++ \
               "$SRC"/capnp-schema-parser-fuzzer.c++ \
               "$SRC"/capnp-text-fuzzer.c++; do
    name=$(basename "$harness" .c++)
    $CXX $CXXFLAGS -std=gnu++23 -stdlib=libc++ \
        -I src \
        "$harness" \
        $EXTRA_LIBS \
        $LIB_FUZZING_ENGINE \
        -lpthread -ldl -lz \
        -o "$OUT/$name"
done

# Build seed corpora directly from the upstream test-data tree so we don't
# need to vendor binary fixtures into the oss-fuzz repo.
TD="$SRC/capnproto/c++/src/capnp/testdata"
zip -j "$OUT/capnp-packed-fuzzer_seed_corpus.zip" \
    "$TD/packed" "$TD/packedflat" "$TD/segmented-packed"
zip -j "$OUT/capnp-json-fuzzer_seed_corpus.zip" \
    "$TD/short.json" "$TD/pretty.json" "$TD/annotated.json"
zip -j "$OUT/capnp-text-fuzzer_seed_corpus.zip" \
    "$TD/short.txt" "$TD/pretty.txt"
# Schema-parser seeds: real upstream .capnp source files plus our tiny one.
zip -j "$OUT/capnp-schema-parser-fuzzer_seed_corpus.zip" \
    "$SRC/capnproto/c++/src/capnp/c++.capnp" \
    "$SRC/capnproto/c++/src/capnp/persistent.capnp" \
    "$SRC/capnproto/c++/src/capnp/stream.capnp" \
    "$SRC/capnproto/c++/src/capnp/compiler/grammar.capnp" \
    "$SRC/capnproto/c++/src/capnp/compiler/lexer.capnp" \
    "$SRC/seeds/capnp-schema-parser-fuzzer/tiny.capnp"

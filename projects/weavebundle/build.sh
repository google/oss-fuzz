#!/bin/bash -eu

cd "$SRC/weavebundle"

cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DWEAVEBUNDLE_ENABLE_FUZZING=ON

cmake --build build --target fuzz_parser

cp build/fuzz_parser "$OUT/"

mkdir -p $OUT/fuzz_parser_seed_corpus
cp examples/*.wvbf $OUT/fuzz_parser_seed_corpus/
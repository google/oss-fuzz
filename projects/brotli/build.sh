#!/bin/bash -eu

cmake . -DBUILD_TESTING=OFF
make clean
make -j$(nproc) brotlidec-static

$CXX $CXXFLAGS -std=c99 -I. \
    c/fuzz/decode_fuzzer.c -I./c/include -o $OUT/decode_fuzzer \
    -lFuzzingEngine ./libbrotlidec-static.a ./libbrotlicommon-static.a

cp java/org/brotli/integration/fuzz_data.zip $OUT/decode_fuzzer_seed_corpus.zip
chmod a-x $OUT/decode_fuzzer_seed_corpus.zip # we will try to run it otherwise

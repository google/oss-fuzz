#!/bin/bash -eu

cmake . -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF
make clean
make -j$(nproc) brotlidec

$CXX $CXXFLAGS -std=c++11 -I. \
    c/fuzz/decode_fuzzer.cc -I./c/include -o $OUT/decode_fuzzer \
    -lFuzzingEngine ./libbrotlidec.a ./libbrotlicommon.a

cp java/org/brotli/integration/fuzz_data.zip $OUT/decode_fuzzer_seed_corpus.zip
chmod a-x $OUT/decode_fuzzer_seed_corpus.zip # we will try to run it otherwise

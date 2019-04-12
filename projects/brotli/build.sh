#!/bin/bash -eu

cmake . -DBUILD_TESTING=OFF
make clean
make -j$(nproc) brotlidec-static

$CC $CFLAGS -c -std=c99 -I. -I./c/include c/fuzz/decode_fuzzer.c 

$CXX $CXXFLAGS ./decode_fuzzer.o  -o $OUT/decode_fuzzer \
    $LIB_FUZZING_ENGINE ./libbrotlidec-static.a ./libbrotlicommon-static.a

cp java/org/brotli/integration/fuzz_data.zip $OUT/decode_fuzzer_seed_corpus.zip
chmod a-x $OUT/decode_fuzzer_seed_corpus.zip # we will try to run it otherwise

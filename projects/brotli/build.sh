#!/bin/bash -eu

cmake . -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF
make -j$(nproc) clean
make -j$(nproc) all

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/brotli_uncompress_fuzzer.cc -o $OUT/brotli_uncompress_fuzzer \
    -lfuzzer -I./include ./libbrotlicommon.a ./libbrotlidec.a

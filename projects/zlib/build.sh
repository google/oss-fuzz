#!/bin/bash -eu

./configure
make -j$(nproc) clean
make -j$(nproc) all

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/zlib_uncompress_fuzzer.cc -o $OUT/zlib_uncompress_fuzzer \
    -lFuzzingEngine ./libz.a

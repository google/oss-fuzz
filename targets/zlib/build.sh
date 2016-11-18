#!/bin/bash -eu

./configure
make -j$(nproc) clean all

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/zlib_uncompress_fuzzer.cc -o $OUT/zlib_uncompress_fuzzer \
    -lfuzzer ./libz.a

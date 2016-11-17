#!/bin/bash -eu

./configure
make -j$(nproc) clean all

$CXX $CXXFLAGS -std=c++11 -I. \
    /src/zlib_uncompress_fuzzer.cc -o /out/zlib_uncompress_fuzzer \
    -lfuzzer ./libz.a $FUZZER_LDFLAGS

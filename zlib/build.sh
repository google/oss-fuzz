#!/bin/bash -eu

cd /src/zlib

./configure
make clean all

$CXX $CXXFLAGS -std=c++11 -I. \
    /src/oss-fuzz/zlib/zlib_uncompress_fuzzer.cc -o /out/zlib_uncompress_fuzzer \
    /work/libfuzzer/*.o ./libz.a $LDFLAGS

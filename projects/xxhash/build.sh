#!/bin/bash -eu
# Build xxHash fuzz target.
# xxHash is header-only (single-header mode); no library build needed.

cd $SRC/xxHash

$CXX $CXXFLAGS -std=c++11 \
    $SRC/xxhash_fuzzer.cc \
    -I . \
    $LIB_FUZZING_ENGINE \
    -o $OUT/xxhash_fuzzer

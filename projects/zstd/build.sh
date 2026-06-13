#!/bin/bash -eu
# Build libzstd and the fuzz target.

cd $SRC/zstd

# Build libzstd static library.
make -C lib libzstd.a \
    CC="$CC" \
    CFLAGS="$CFLAGS" \
    -j$(nproc)

# Build fuzz target.
$CXX $CXXFLAGS -std=c++11 \
    $SRC/zstd_fuzzer.cc \
    -I lib \
    lib/libzstd.a \
    $LIB_FUZZING_ENGINE \
    -o $OUT/zstd_fuzzer

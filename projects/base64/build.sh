#!/bin/bash -eu
# Build aklomp/base64 and the fuzz target.

cd $SRC/base64

# Build via cmake (preferred; selects SSSE3/AVX2 codecs automatically).
cmake -S . -B build \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBASE64_BUILD_TESTS=OFF

cmake --build build --parallel $(nproc)

# Build fuzz target.
$CXX $CXXFLAGS -std=c++11 \
    $SRC/base64_fuzzer.cc \
    -I include \
    build/lib/libbase64.a \
    $LIB_FUZZING_ENGINE \
    -o $OUT/base64_fuzzer

#!/bin/bash -eu

SRC_DIR="$SRC/fbthrift"
BUILD_DIR="$WORK/build"

cmake -S "$SRC_DIR/thrift/lib/cpp/protocol" -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS"

cmake --build "$BUILD_DIR" --target fuzz_thrift -j"$(nproc)"

cp "$BUILD_DIR/fuzz_thrift" "$OUT/"

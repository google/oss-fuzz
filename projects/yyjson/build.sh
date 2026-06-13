#!/bin/bash -eu
# Build yyjson and the fuzz target.
# yyjson is a single-header / single-source library.

cd $SRC/yyjson

# Build yyjson as an object file (C source, compile with CXX driver).
$CC $CFLAGS -c src/yyjson.c -o yyjson.o

# Build fuzz target (C++ wrapper).
$CXX $CXXFLAGS -std=c++11 \
    $SRC/yyjson_fuzzer.cc \
    yyjson.o \
    -I src \
    $LIB_FUZZING_ENGINE \
    -o $OUT/yyjson_fuzzer

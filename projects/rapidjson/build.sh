#!/bin/bash -eu
# Build rapidjson fuzz target.
# rapidjson is header-only; no separate library build step needed.

cd $SRC/rapidjson

$CXX $CXXFLAGS -std=c++11 \
    $SRC/rapidjson_fuzzer.cc \
    -I include \
    $LIB_FUZZING_ENGINE \
    -o $OUT/rapidjson_fuzzer

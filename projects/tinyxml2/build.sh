#!/bin/bash -eu
# Build tinyxml2 as a static library then link the fuzz target.

cd $SRC/tinyxml2

# Build tinyxml2 object file
$CXX $CXXFLAGS -std=c++11 -c tinyxml2.cpp -o tinyxml2.o

# Build fuzz target
$CXX $CXXFLAGS -std=c++11 \
    $SRC/tinyxml2_fuzzer.cc \
    tinyxml2.o \
    -I. \
    $LIB_FUZZING_ENGINE \
    -o $OUT/tinyxml2_fuzzer

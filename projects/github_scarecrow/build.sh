#!/bin/bash -eu

$CXX $CXXFLAGS -std=c++11 -Ilib/ \
    $SRC/github-scarecrow/scarecrow.cc -o $OUT/scarecrow \
    $LIB_FUZZING_ENGINE
#!/bin/bash -eu

mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX:PATH=$PWD/install_dir/
make -j$(nproc) inkscape_base

$CXX $CXXFLAGS -std=c++11 -Ilib/ ${SRC}/fuzzer.cpp -o $OUT/fuzzer \
    -lFuzzingEngine lib/*

cp $SRC/fuzz-dict $OUT/fuzz.dict



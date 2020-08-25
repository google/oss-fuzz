#!/bin/bash
cd $SRC/libyuv
mkdir build
cd build
cmake ../

make clean
make -j$(nproc) all

$CXX $CXXFLAGS -I ../include/ \
    $SRC/libyuv_fuzzer.cc -o $OUT/libyuv_fuzzer\
    $LIB_FUZZING_ENGINE ./libyuv.a

cp  $SRC/*.options $OUT/

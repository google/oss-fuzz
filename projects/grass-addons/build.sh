#!/bin/bash -eu

mkdir build
cd build
cmake ..
make -j$(nproc)

$CXX $CXXFLAGS -I /src/grass-addons/include /src/grass-addons/fuzz_target.c -o $OUT/fuzz_target \
    $LIB_FUZZING_ENGINE /src/grass-addons/src/*.o
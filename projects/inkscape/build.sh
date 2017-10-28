#!/bin/bash -eu

mkdir build
cd build
cmake .. -DWITH_FUZZ=ON -DLIB_FUZZING_ENGINE=ON -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX:PATH=$PWD/install_dir/
make -j$(nproc) inkscape_base
VERBOSE=1 make fuzz

cp bin/fuzz $OUT/


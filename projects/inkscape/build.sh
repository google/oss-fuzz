#!/bin/bash -eu

mkdir build
cd build
cmake .. -DWITH_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX:PATH=$PWD/install_dir/
make -j$(nproc) fuzz


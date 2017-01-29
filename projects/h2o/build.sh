#!/bin/bash -eu

set -x

pushd $SRC/h2o
git apply $SRC/fixup.patch
popd
CXX=clang++ CC=clang cmake -DBUILD_FUZZER=ON -DWITH_BUNDLED_SSL=ON -DOSS_FUZZ=ON .
make

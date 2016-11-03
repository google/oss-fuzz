#!/bin/bash -eu
cd /src/expat/expat

./buildconf.sh
./configure
make clean
make -j$(nproc) all

$CXX $CXXFLAGS -std=c++11 -Ilib/ \
    /src/parse_fuzzer.cc -o /out/parse_fuzzer \
    -lfuzzer .libs/libexpat.a $FUZZER_LDFLAGS

cp /src/*.dict /src/*.options /out/

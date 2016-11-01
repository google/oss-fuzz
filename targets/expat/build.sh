#!/bin/bash -eu
cd /src/expat/expat

./buildconf.sh
./configure
make -j$(nproc) clean all

$CXX $CXXFLAGS -std=c++11 -Ilib/ \
    /src/parse_fuzzer.cc -o /out/parse_fuzzer \
    -lfuzzer .libs/libexpat.a $FUZZER_LDFLAGS

cp /src/*.dict /src/*.options /out/

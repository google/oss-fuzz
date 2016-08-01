#!/bin/bash -ex
. /env

cd /workspace/expat

./buildconf.sh
./configure
make clean all

$CXX $CXXFLAGS $LDFLAGS -std=c++11 -Ilib/ \
    /src/oss-fuzz/expat/parse_fuzzer.cc -o /out/expat_parse_fuzzer \
    /work/libfuzzer/*.o .libs/libexpat.a

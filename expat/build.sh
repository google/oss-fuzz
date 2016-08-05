#!/bin/bash -ex
. /env

cd /src/expat/expat

./buildconf.sh
./configure
make clean all

$CXX $CXXFLAGS -std=c++11 -Ilib/ \
    /src/oss-fuzz/expat/parse_fuzzer.cc -o /out/expat_parse_fuzzer \
    /work/libfuzzer/*.o .libs/libexpat.a $LDFLAGS

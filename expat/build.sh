#!/bin/bash -ex
. /env

cd /workspace/expat
ls -alR

./buildconf.sh
./configure
make clean all

$CXX $CXXFLAGS -std=c++11 -Ilib/ \
    /src/oss-fuzz/expat/parse_fuzzer.cc -o /out/parse_fuzzer \
    /work/libfuzzer/*.o .libs/libexpat.a

#!/bin/bash -eu
cd /src/libxml2

./configure
make clean all

for fuzzer in libxml2_xml_read_memory_fuzzer libxml2_xml_regexp_compile_fuzzer; do
  $CXX $CXXFLAGS -std=c++11 -Iinclude/ \
      /src/oss-fuzz/libxml2/$fuzzer.cc -o /out/$fuzzer \
      /work/libfuzzer/*.o .libs/libxml2.a $LDFLAGS
done

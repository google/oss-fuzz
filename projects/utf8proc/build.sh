#!/bin/bash -eu
# Build utf8proc and the fuzz target.

cd $SRC/utf8proc

# Build in strict C99 mode matching the library's own Makefile.
$CC $CFLAGS -c utf8proc.c -o utf8proc.o

# Build fuzz target (C++ wrapper links against the object file).
$CXX $CXXFLAGS -std=c++11 \
    $SRC/utf8proc_fuzzer.cc \
    utf8proc.o \
    -I . \
    $LIB_FUZZING_ENGINE \
    -o $OUT/utf8proc_fuzzer

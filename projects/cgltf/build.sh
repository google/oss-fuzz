#!/bin/bash
find . -name "*.c" -exec $CC $CFLAGS -I./src -c {} \;
find . -name "*.o" -exec cp {} . \;

rm -f ./test*.o
llvm-ar rcs libfuzz.a *.o


$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $SRC/fuzzer.cpp -Wl,--whole-archive $SRC/cgltf/libfuzz.a -Wl,--allow-multiple-definition  -I$SRC/cgltf/  -o $OUT/fuzzer
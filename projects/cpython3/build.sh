#!/bin/bash

# Ignore memory leaks from python scripts invoked in the build
export ASAN_OPTIONS="detect_leaks=0"

# Remove -pthread from CFLAGS, this trips up ./configure
# which thinks pthreads are available without any CLI flags
CFLAGS=${CFLAGS//"-pthread"/}

FLAGS=""
case $SANITIZER in
  address)
    FLAGS="--with-address-sanitizer"
    ;;
  memory)
    FLAGS="--with-memory-sanitizer"
    ;;
  undefined)
    FLAGS="--with-undefined-behavior-sanitizer"
    ;;
esac
./configure $FLAGS --prefix $OUT

make -j$(nproc) install

FUZZ_DIR=Modules/_xxtestfuzz
for fuzz_test in $(cat $FUZZ_DIR/fuzz_tests.txt)
do
  # Build (but don't link) the fuzzing stub with a C compiler
  $CC $CFLAGS $($OUT/bin/python3-config --cflags) $FUZZ_DIR/fuzzer.c \
    -D _Py_FUZZ_ONE -D _Py_FUZZ_$fuzz_test -c -Wno-unused-function \
    -o $WORK/$fuzz_test.o
  # Link with C++ compiler to appease libfuzzer
  $CXX $CXXFLAGS $WORK/$fuzz_test.o -o $OUT/$fuzz_test \
    $LIB_FUZZING_ENGINE $($OUT/bin/python3-config --ldflags --embed)
done

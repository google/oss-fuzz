#!/bin/bash -eu

# afl++ workaround, this also randomly enables CMPLOG lite
test -n "$AFL_MAP_SIZE" && {
  export CC=clang
  export CXX=clang++
  AFL_FLAGS="-fsanitize-coverage=trace-pc-guard"
  rm -f $WORK/afl_cmplog
  # 40% chance for cmplog lite
  test $(($RANDOM % 10)) -lt 4 && {
    AFL_FLAGS="$AFL_FLAGS,trace-cmp"
    touch $WORK/afl_cmplog
  }
  export CFLAGS="$AFL_FLAGS $CFLAGS"
  export CXXFLAGS="$AFL_FLAGS $CXXFLAGS"
  rm -f $LIB_FUZZING_ENGINE
  ar ru $LIB_FUZZING_ENGINE $SRC/aflplusplus/afl-compiler-rt.o $SRC/aflplusplus/utils/aflpp_driver/aflpp_driver.o || exit 1
}

$SRC/libreoffice/bin/oss-fuzz-build.sh

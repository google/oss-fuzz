#!/bin/bash -eu

./configure
make -j$(nproc) clean
make -j$(nproc) all

# Do not make check as there are tests that fail when compiled with MSAN.
# make -j$(nproc) check

$CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/zlib_uncompress_fuzzer.cc -o $OUT/zlib_uncompress_fuzzer \
    $LIB_FUZZING_ENGINE ./libz.a

zip $OUT/seed_corpus.zip *.*

for f in $(find $SRC -name '*_fuzzer.c'); do
    b=$(basename -s .c $f)
    $CC $CFLAGS -I. $f -c -o /tmp/$b.o
    $CXX $CXXFLAGS -o $OUT/$b /tmp/$b.o -stdlib=libc++ $LIB_FUZZING_ENGINE ./libz.a
    rm -f /tmp/$b.o
    ln -sf $OUT/seed_corpus.zip $OUT/${b}_seed_corpus.zip
done

#!/bin/bash -eu

# Oops, reset the flags provided by OSS-Fuzz.
export CFLAGS="-O1"
export CXXFLAGS="-O1 -stdlib=libc++"

./configure
make -j$(nproc) clean
make -j$(nproc) all

$CXX -fsanitize=$SANITIZER $CXXFLAGS -std=c++11 -I. \
    $SRC/zlib_uncompress_fuzzer.cc -o $OUT/zlib_uncompress_fuzzer \
    -lFuzzingEngine ./libz.a

# Ways to detect:
#
# 1. Execute "/out/zlib_uncompress_fuzzer -max_total_time=4"
#    Look for "ERROR: no interesting inputs were found. Is the code instrumented for coverage? Exiting."
#
# 2. Execute "sancov -print-coverage-pcs zlib_uncompress_fuzzer | wc -l"
#    Should be 90 at least. The "example" target has 93. Real targets values:
#    arduinojson: 413, libteken: 519, zlib: 586.
#
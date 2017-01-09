#!/bin/bash -eu

sh autogen.sh

# We need to run configure with leak-checking disabled, or many of the
# test functions will fail.
export ASAN_OPTIONS=detect_leaks=0

./configure --disable-asciidoc --enable-oss-fuzz
make clean
make -j$(nproc) oss-fuzz-fuzzers
cp src/test/fuzz/oss-fuzz-* $(OUT)

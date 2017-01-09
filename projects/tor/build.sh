#!/bin/bash -eu

sh autogen.sh

# We need to run configure with leak-checking disabled, or many of the
# test functions will fail.
export ASAN_OPTIONS=detect_leaks=0

./configure --disable-asciidoc --enable-oss-fuzz
make clean
make -j$(nproc) oss-fuzz-fuzzers

TORLIBS="src/or/libtor-testing.a"
TORLIBS="$TORLIBS src/common/libor-crypto-testing.a"
TORLIBS="$TORLIBS src/ext/keccak-tiny/libkeccak-tiny.a"
TORLIBS="$TORLIBS src/common/libcurve25519_donna.a"
TORLIBS="$TORLIBS src/ext/ed25519/ref10/libed25519_ref10.a"
TORLIBS="$TORLIBS src/ext/ed25519/donna/libed25519_donna.a"
TORLIBS="$TORLIBS src/common/libor-testing.a"
TORLIBS="$TORLIBS src/common/libor-ctime-testing.a"
TORLIBS="$TORLIBS src/common/libor-event-testing.a"
TORLIBS="$TORLIBS src/trunnel/libor-trunnel-testing.a"
TORLIBS="$TORLIBS -lz -lm -levent -lssl -lcrypto"

for fuzzer in src/test/fuzz/*.a; do
    output="${fuzzer%.a}"
    output="${output##*lib}"
    ${CXX} ${CXXFLAGS} -std=c++11 -lFuzzingEngine ${fuzzer} ${TORLIBS} -o ${OUT}/${output}
done

cd $WORK


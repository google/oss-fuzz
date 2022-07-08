#!/bin/bash -eu

DIR=$SRC/libwebsockets/

cd $DIR
mkdir build && cd build

cmake -DCMAKE_C_FLAGS="$CFLAGS -fsanitize=address,fuzzer-no-link -g" -DCMAKE_CXX_FLAGS="$CXXFLAGS -fsanitize=address,fuzzer-no-link -g" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,fuzzer-no-link -g" -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,fuzzer-no-link -g" ..
make -j8

cd $DIR
$CXX -g -fsanitize=address,fuzzer -I$DIR/build/include -o $OUT/lws_upng_inflate_fuzzer lws_upng_inflate_fuzzer.cpp -L$DIR/build/lib -l:libwebsockets.a -L/usr/lib/x86_64-linux-gnu/ -l:libssl.so -l:libcrypto.so

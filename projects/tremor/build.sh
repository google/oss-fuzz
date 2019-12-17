#!/bin/bash -eu

pushd $SRC/ogg
./autogen.sh
./configure --prefix="$WORK" --enable-static --disable-shared --disable-crc
make clean
make -j$(nproc)
make install
popd

./autogen.sh --prefix="$WORK" --enable-static --disable-shared
make clean
make -j$(nproc)
make install

$CXX $CXXFLAGS decode_fuzzer.cc -o $OUT/decode_fuzzer -L"$WORK/lib" -I"$WORK/include" -lFuzzingEngine -lvorbisidec -logg

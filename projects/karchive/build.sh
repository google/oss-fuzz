#!/bin/bash -eu
# Copyright 2019 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# build zstd
cd $SRC/zstd
cmake -S build/cmake -DBUILD_SHARED_LIBS=OFF
make install -j$(nproc)

# Build zlib
cd $SRC/zlib
./configure --static
make install -j$(nproc)

# Build libzip
cd $SRC/libzip
cmake . -DBUILD_SHARED_LIBS=OFF
make install -j$(nproc)

# Build bzip2
# Inspired from ../bzip2/build
cd $SRC
tar xzf bzip2-*.tar.gz && rm -f bzip2-*.tar.gz
cd bzip2-*
SRCL=(blocksort.o huffman.o crctable.o randtable.o compress.o decompress.o bzlib.o)

for source in ${SRCL[@]}; do
    name=$(basename $source .o)
    $CC $CFLAGS -c ${name}.c
done
rm -f libbz2.a
ar cq libbz2.a ${SRCL[@]}
cp -f bzlib.h /usr/local/include
cp -f libbz2.a /usr/local/lib

# Build xz
export ORIG_CFLAGS="${CFLAGS}"
export ORIG_CXXFLAGS="${CXXFLAGS}"
unset CFLAGS
unset CXXFLAGS
cd $SRC/xz
./autogen.sh --no-po4a --no-doxygen
./configure --enable-static --disable-debug --disable-shared --disable-xz --disable-xzdec --disable-lzmainfo
make install -j$(nproc)
export CFLAGS="${ORIG_CFLAGS}"
export CXXFLAGS="${ORIG_CXXFLAGS}"

# Build openssl
cd $SRC/openssl
CONFIG_FLAGS="no-shared no-tests"
if [[ $CFLAGS = *sanitize=memory* ]]
then
    # Disable assembly for proper instrumentation
    CONFIG_FLAGS+=" no-asm"
fi
./config $CONFIG_FLAGS
make -j$(nproc)
make install_sw

# Build extra-cmake-modules
cd $SRC/extra-cmake-modules
cmake .
make install -j$(nproc)

# Build qtbase
cd $SRC/qtbase
./configure -no-glib -qt-libpng -qt-pcre -opensource -confirm-license -static -no-opengl -no-icu -platform linux-clang-libc++ -debug -prefix /usr -no-feature-gui -no-feature-sql -no-feature-network  -no-feature-xml -no-feature-dbus -no-feature-printsupport
cmake --build . --parallel $(nproc)
cmake --install .


# Build karchive
cd $SRC
cd karchive
rm -rf poqm
cmake . -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF
make install -j$(nproc)

# Build karchive_fuzzer
$CXX $CXXFLAGS -fPIC -std=c++17 $SRC/karchive_fuzzer.cc -o $OUT/karchive_fuzzer -I /usr/include/QtCore/ -I /usr/local/include/KF6/KArchive -lQt6Core -lm -lQt6BundledPcre2 -ldl -lpthread $LIB_FUZZING_ENGINE /usr/local/lib/libzip.a /usr/local/lib/libz.a -lKF6Archive /usr/local/lib/libbz2.a -llzma /usr/local/lib/libzstd.a /usr/local/lib64/libcrypto.a

cd $SRC
find . -name "*.gz" -o -name "*.zip" -o -name "*.xz" -o -name "*.tar" -o -name "*.7z" | zip -q $OUT/karchive_fuzzer_seed_corpus.zip -@

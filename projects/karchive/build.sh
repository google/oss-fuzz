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
cd $SRC
cd zstd
cmake -S build/cmake -DBUILD_SHARED_LIBS=OFF
make install -j$(nproc)

# Build zlib
cd $SRC
cd zlib
./configure --static
make install -j$(nproc)

# Build libzip
cd $SRC
cd libzip
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
cd $SRC
cd xz
./autogen.sh --no-po4a --no-doxygen
./configure --enable-static --disable-debug --disable-shared --disable-xz --disable-xzdec --disable-lzmainfo
make install -j$(nproc)
export CFLAGS="${ORIG_CFLAGS}"
export CXXFLAGS="${ORIG_CXXFLAGS}"

# Build extra-cmake-modules
cd $SRC
cd extra-cmake-modules
cmake .
make install -j$(nproc)

# Build qtbase
cd $SRC
cd qtbase
# add the flags to Qt build too
# Use ~ as sed delimiters instead of the usual "/" because C(XX)FLAGS may
# contain paths with slashes.
sed -i -e "s~QMAKE_CXXFLAGS    += -stdlib=libc++~QMAKE_CXXFLAGS    += -stdlib=libc++  $CXXFLAGS\nQMAKE_CFLAGS += $CFLAGS~g" mkspecs/linux-clang-libc++/qmake.conf
sed -i -e "s~QMAKE_LFLAGS      += -stdlib=libc++~QMAKE_LFLAGS      += -stdlib=libc++ -lpthread $CXXFLAGS~g" mkspecs/linux-clang-libc++/qmake.conf
sed -i -e "s~QMAKE_CXX               = \$\${CROSS_COMPILE}clang++~QMAKE_CXX = $CXX~g" mkspecs/common/clang.conf
sed -i -e "s~QMAKE_CC                = \$\${CROSS_COMPILE}clang~QMAKE_CC = $CC~g" mkspecs/common/clang.conf
./configure -no-glib -qt-libpng -qt-pcre -opensource -confirm-license -static -no-opengl -no-icu -platform linux-clang-libc++ -debug -prefix /usr
cmake --build . --parallel $(nproc)
cmake --install .


# Build karchive
cd $SRC
cd karchive
rm -rf poqm
cmake . -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF
make install -j$(nproc)

# Build karchive_fuzzer
$CXX $CXXFLAGS -fPIC -std=c++17 $SRC/karchive_fuzzer.cc -o $OUT/karchive_fuzzer -I $SRC/qtbase/include/QtCore/ -I $SRC/qtbase/include/ -I $SRC/qtbase/include/QtGui -I $SRC/qtbase/mkspecs/linux-clang-libc++/ -I /usr/local/include/KF6/KArchive -L $SRC/qtbase/lib -lQt6Core -lm -lqtpcre2 -ldl -lpthread $LIB_FUZZING_ENGINE /usr/local/lib/libzip.a /usr/local/lib/libz.a -lKF6Archive /usr/local/lib/libbz2.a -llzma /usr/local/lib/libzstd.a

cd $SRC
find . -name "*.gz" -o -name "*.zip" -o -name "*.xz" -o -name "*.tar" | zip -q $OUT/karchive_fuzzer_seed_corpus.zip -@

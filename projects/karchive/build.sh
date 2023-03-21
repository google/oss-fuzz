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
cd $SRC
cd xz
./autogen.sh --no-po4a --no-doxygen
./configure --enable-static --disable-debug --disable-shared --disable-xz --disable-xzdec --disable-lzmainfo
make install -j$(nproc)

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
# make qmake compile faster
sed -i -e "s/MAKE\")/MAKE\" -j$(nproc))/g" configure
# add QT_NO_WARNING_OUTPUT to make the output a bit cleaner by not containing lots of QBuffer::seek: Invalid pos
sed -i -e "s/DEFINES += QT_NO_USING_NAMESPACE QT_NO_FOREACH/DEFINES += QT_NO_USING_NAMESPACE QT_NO_FOREACH QT_NO_WARNING_OUTPUT/g" src/corelib/corelib.pro
./configure --glib=no --libpng=qt -opensource -confirm-license -static -no-opengl -no-icu -platform linux-clang-libc++ -v
cd src
../bin/qmake -o Makefile src.pro
make sub-corelib sub-rcc -j$(nproc)

# Build karchive
cd $SRC
cd karchive
rm -rf poqm
cmake . -DBUILD_SHARED_LIBS=OFF -DQt5Core_DIR=$SRC/qtbase/lib/cmake/Qt5Core/ -DBUILD_TESTING=OFF
make install -j$(nproc)

# Build karchive_fuzzer
$CXX $CXXFLAGS -fPIC -std=c++11 $SRC/karchive_fuzzer.cc -o $OUT/karchive_fuzzer -I $SRC/qtbase/include/QtCore/ -I $SRC/qtbase/include/ -I $SRC/qtbase/include//QtGui -I $SRC/qtbase/mkspecs/linux-clang-libc++/ -I /usr/local/include/KF5/KArchive -L $SRC/qtbase/lib -lQt5Core -lm -lqtpcre2 -ldl -lpthread $LIB_FUZZING_ENGINE /usr/local/lib/libzip.a /usr/local/lib/libz.a -lKF5Archive /usr/local/lib/libbz2.a -llzma -lQt5Core /usr/local/lib/libz.a

cd $SRC
find . -name "*.gz" -o -name "*.zip" -o -name "*.xz" -o -name "*.tar" | zip -q $OUT/karchive_fuzzer_seed_corpus.zip -@

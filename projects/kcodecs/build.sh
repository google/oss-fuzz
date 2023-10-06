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

cd $SRC
tar xzf gperf*.tar.gz && rm -f gperf*.tar.gz
cd gperf*
FUZZ_CFLAGS="${CFLAGS}"
FUZZ_CXXFLAGS="${CXXFLAGS}"
unset CFLAGS
unset CXXFLAGS
# gperf is a code generator, so no need to sanitize it
./configure --prefix=/usr
make -j$(nproc) install
export CFLAGS="${FUZZ_CFLAGS}"
export CXXFLAGS="${FUZZ_CXXFLAGS}"


cd $SRC
cd extra-cmake-modules
cmake .
make install

cd $SRC
cd qtbase
# add the flags to Qt build too
# Use ~ as sed delimiters instead of the usual "/" because C(XX)FLAGS may
# contain paths with slashes.
sed -i -e "s~QMAKE_CXXFLAGS    += -stdlib=libc++~QMAKE_CXXFLAGS    += -stdlib=libc++  $CXXFLAGS\nQMAKE_CFLAGS += $CFLAGS~g" mkspecs/linux-clang-libc++/qmake.conf
sed -i -e "s~QMAKE_LFLAGS      += -stdlib=libc++~QMAKE_LFLAGS      += -stdlib=libc++ -lpthread $CXXFLAGS~g" mkspecs/linux-clang-libc++/qmake.conf
# make qmake compile faster
sed -i -e "s/MAKE\")/MAKE\" -j$(nproc))/g" configure
./configure --zlib=qt --glib=no --libpng=qt -opensource -confirm-license -static -no-opengl -no-icu -platform linux-clang-libc++ -v
cd src
../bin/qmake -o Makefile src.pro
make sub-corelib sub-rcc -j$(nproc)

cd $SRC
cd kcodecs
rm -rf poqm
cmake . -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=$SRC/qtbase
make -j$(nproc) VERBOSE=1


$CXX $CXXFLAGS -fPIC -std=c++11 $SRC/kcodecs_fuzzer.cc -o $OUT/kcodecs_fuzzer \
               -I $SRC/qtbase/include/QtCore/ -I $SRC/qtbase/include/ -I $SRC/kcodecs/src \
               -I $SRC/kcodecs/src/probers -L $SRC/qtbase/lib -L $SRC/kcodecs/lib \
               -lQt5Core -lm -lqtpcre2 -ldl -lpthread $LIB_FUZZING_ENGINE -lKF5Codecs

zip -qr $OUT/kcodecs_fuzzer_seed_corpus.zip $SRC/uchardet/test/ $SRC/kcodecs/autotests/data

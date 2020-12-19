#!/bin/bash -eu
# Copyright 2020 Google LLC
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
cd zlib
./configure --static
make install -j$(nproc)

cd $SRC
cd libzip
cmake . -DBUILD_SHARED_LIBS=OFF
make install -j$(nproc)

cd $SRC
cd extra-cmake-modules
cmake .
make install -j$(nproc)

cd $SRC
cd qtbase
# add the flags to Qt build too
sed -i -e "s/QMAKE_CXXFLAGS    += -stdlib=libc++/QMAKE_CXXFLAGS    += -stdlib=libc++  $CXXFLAGS\nQMAKE_CFLAGS += $CFLAGS/g" mkspecs/linux-clang-libc++/qmake.conf
sed -i -e "s/QMAKE_LFLAGS      += -stdlib=libc++/QMAKE_LFLAGS      += -stdlib=libc++ -lpthread $CXXFLAGS/g" mkspecs/linux-clang-libc++/qmake.conf
# disable sanitize=vptr for harfbuzz since it compiles without rtti
sed -i -e "s/TARGET = qtharfbuzz/TARGET = qtharfbuzz\nQMAKE_CXXFLAGS += -fno-sanitize=vptr/g" src/3rdparty/harfbuzz-ng/harfbuzz-ng.pro
# make qmake compile faster
sed -i -e "s/MAKE\")/MAKE\" -j$(nproc))/g" configure
./configure --glib=no --libpng=qt -opensource -confirm-license -static -no-opengl -no-icu -platform linux-clang-libc++ -v
cd src
../bin/qmake -o Makefile src.pro
make sub-gui -j$(nproc)

cd $SRC
cd karchive
cmake . -DBUILD_SHARED_LIBS=OFF -DQt5Core_DIR=$SRC/qtbase/lib/cmake/Qt5Core/ -DBUILD_TESTING=OFF
make install -j$(nproc)

cd $SRC
cd aom
mkdir build.libavif
cd build.libavif
extra_libaom_flags='-DAOM_MAX_ALLOCABLE_MEMORY=536870912 -DDO_RANGE_CHECK_CLAMP=1'
cmake -DBUILD_SHARED_LIBS=0 -DENABLE_DOCS=0 -DENABLE_EXAMPLES=0 -DENABLE_TESTDATA=0 -DENABLE_TESTS=0 -DENABLE_TOOLS=0 -DCONFIG_PIC=1 -DAOM_TARGET_CPU=generic -DCONFIG_SIZE_LIMIT=1 -DDECODE_HEIGHT_LIMIT=12288 -DDECODE_WIDTH_LIMIT=12288 -DAOM_EXTRA_C_FLAGS="${extra_libaom_flags}" -DAOM_EXTRA_CXX_FLAGS="${extra_libaom_flags}" ..
make -j$(nproc)

cd $SRC
ln -s "$SRC/aom" "$SRC/libavif/ext/"
cd libavif
mkdir build
cd build
CFLAGS="$CFLAGS -fPIC" cmake -DBUILD_SHARED_LIBS=OFF -DAVIF_ENABLE_WERROR=OFF -DAVIF_CODEC_AOM=ON -DAVIF_LOCAL_AOM=ON ..
make -j$(nproc)

cd $SRC
cd kimageformats
HANDLER_TYPES="QAVIFHandler avif
        KraHandler kra
        OraHandler ora
        PCXHandler pcx
        SoftimagePICHandler pic
        PSDHandler psd
        RASHandler ras
        RGBHandler rgb
        TGAHandler tga
        XCFHandler xcf"

echo "$HANDLER_TYPES" | while read class format; do
(
  fuzz_target_name=kimgio_${format}_fuzzer

  $SRC/qtbase/bin/moc $SRC/kimageformats/src/imageformats/$format.cpp -o $format.moc
  $CXX $CXXFLAGS -fPIC -DHANDLER=$class -std=c++14 $SRC/kimgio_fuzzer.cc $SRC/kimageformats/src/imageformats/$format.cpp -o $OUT/$fuzz_target_name -I $SRC/qtbase/include/QtCore/ -I $SRC/qtbase/include/ -I $SRC/qtbase/include//QtGui -I $SRC/kimageformats/src/imageformats/ -I $SRC/karchive/src/ -I $SRC/qtbase/mkspecs/linux-clang-libc++/ -I $SRC/libavif/include/ -I . -L $SRC/qtbase/lib $SRC/libavif/build/libavif.a $SRC/aom/build.libavif/libaom.a -lQt5Gui -lQt5Core -lqtlibpng -lqtharfbuzz -lm -lqtpcre2 -ldl -lpthread $LIB_FUZZING_ENGINE /usr/local/lib/libzip.a /usr/local/lib/libz.a -lKF5Archive

  find . -name "*.${format}" | zip -q $OUT/${fuzz_target_name}_seed_corpus.zip -@
)
done

#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

export LD_LIBRARY_PATH="/usr/lib/x86_64-linux-gnu/"

pushd $SRC/freetype2
./autogen.sh
./configure --prefix="$WORK" --disable-shared PKG_CONFIG_PATH="$WORK/lib/pkgconfig"
make -j$(nproc)
make install

pushd $SRC/Little-CMS
./configure --prefix="$WORK" --disable-shared PKG_CONFIG_PATH="$WORK/lib/pkgconfig"
make -j$(nproc)
make install

mkdir -p $SRC/openjpeg/build
pushd $SRC/openjpeg/build
cmake .. -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=$WORK
make -j$(nproc) install

mkdir -p $SRC/poppler/build
pushd $SRC/poppler/build
cmake .. \
  -DCMAKE_BUILD_TYPE=debug \
  -DBUILD_SHARED_LIBS=OFF \
  -DFONT_CONFIGURATION=generic \
  -DENABLE_DCTDECODER=none \
  -DENABLE_LIBPNG=OFF \
  -DENABLE_ZLIB=OFF \
  -DENABLE_LIBTIFF=OFF \
  -DENABLE_LIBJPEG=OFF \
  -DENABLE_GLIB=ON \
  -DENABLE_LIBCURL=OFF \
  -DENABLE_QT5=ON \
  -DENABLE_UTILS=OFF \
  -DWITH_Cairo=ON \
  -DWITH_NSS3=OFF \
  -DCMAKE_INSTALL_PREFIX=$WORK

make -j$(nproc) poppler poppler-cpp poppler-glib poppler-qt5

fuzzers=$(find $SRC/poppler/cpp/tests/fuzzing/ -name "*_fuzzer.cc")

for f in $fuzzers; do
  fuzzer_name=$(basename $f .cc)

  $CXX $CXXFLAGS -std=c++11 -I$SRC/poppler/cpp \
    $f -o $OUT/$fuzzer_name \
    $LIB_FUZZING_ENGINE \
    $SRC/poppler/build/cpp/libpoppler-cpp.a \
    $SRC/poppler/build/libpoppler.a \
    $WORK/lib/libfreetype.a \
    $WORK/lib/liblcms2.a \
    $WORK/lib/libopenjp2.a \
    -lpng -lz
done

fuzzers=$(find $SRC/poppler/glib/tests/fuzzing/ -name "*_fuzzer.cc")

for f in $fuzzers; do
  fuzzer_name=$(basename $f .cc)

  $CXX $CXXFLAGS -std=c++11 -I$SRC/poppler/glib -I$SRC/poppler/build/glib \
    -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
    -I/usr/include/cairo \
    $f -o $OUT/$fuzzer_name \
    $LIB_FUZZING_ENGINE \
    $SRC/poppler/build/glib/libpoppler-glib.a \
    $SRC/poppler/build/cpp/libpoppler-cpp.a \
    $SRC/poppler/build/libpoppler.a \
    $WORK/lib/libfreetype.a \
    $WORK/lib/liblcms2.a \
    $WORK/lib/libopenjp2.a \
    -lpng -lz \
    -lgio-2.0 -lgobject-2.0 -lglib-2.0 -lcairo-gobject -lpangocairo-1.0 -lcairo
done

fuzzers=$(find $SRC/poppler/qt5/tests/fuzzing/ -name "*_fuzzer.cc")

for f in $fuzzers; do
  fuzzer_name=$(basename $f .cc)

  $CXX $CXXFLAGS -std=c++11 \
    -I/usr/include/x86_64-linux-gnu/qt5 -I$SRC/poppler/qt5/src \
    -fPIC \
    $f -o $OUT/$fuzzer_name \
    $LIB_FUZZING_ENGINE \
    $SRC/poppler/build/qt5/src/libpoppler-qt5.a \
    $SRC/poppler/build/cpp/libpoppler-cpp.a \
    $SRC/poppler/build/libpoppler.a \
    $WORK/lib/libfreetype.a \
    $WORK/lib/liblcms2.a \
    $WORK/lib/libopenjp2.a \
    -lpng -lz \
    -lQt5Gui -lQt5Core -lQt5Xml
done

mv $SRC/{*.zip,*.dict} $OUT

if [ ! -f "${OUT}/poppler_seed_corpus.zip" ]; then
  echo "missing seed corpus"
  exit 1
fi

if [ ! -f "${OUT}/poppler.dict" ]; then
  echo "missing dictionary"
  exit 1
fi

fuzzers=$(find $OUT -name "*_fuzzer")

for f in $fuzzers; do
    fuzzer_name=$(basename $f)
    cp $OUT/poppler.dict $OUT/$fuzzer_name.dict
done

rm $OUT/poppler.dict

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
PREFIX=$WORK/prefix
mkdir -p $PREFIX

export PKG_CONFIG="`which pkg-config` --static"
export PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig
export PATH=$PREFIX/bin:$PATH

BUILD=$WORK/build

rm -rf $WORK/*
rm -rf $BUILD
mkdir -p $BUILD

pushd $SRC/glib-2.64.2
meson \
    --prefix=$PREFIX \
    --libdir=lib \
    --default-library=static \
    -Db_lundef=false \
    -Doss_fuzz=enabled \
    -Dlibmount=disabled \
    -Dinternal_pcre=true \
    _builddir
ninja -C _builddir
ninja -C _builddir install
popd

pushd $SRC/freetype2
./autogen.sh
./configure --prefix="$PREFIX" --disable-shared PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
make -j$(nproc)
make install

pushd $SRC/Little-CMS
./configure --prefix="$PREFIX" --disable-shared PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
make -j$(nproc)
make install

mkdir -p $SRC/openjpeg/build
pushd $SRC/openjpeg/build
cmake .. -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=$PREFIX
make -j$(nproc) install

pushd $SRC/libpng
autoreconf -fi
./configure --prefix="$PREFIX" --disable-shared --disable-dependency-tracking
make -j$(nproc)
make install

pushd $SRC/cairo
meson \
    --prefix=$PREFIX \
    --libdir=lib \
    --default-library=static \
    _builddir
ninja -C _builddir
ninja -C _builddir install
popd

pushd $SRC/pango-1.48.0
meson \
    -Ddefault_library=static \
    --prefix=$PREFIX \
    --libdir=lib \
    _builddir
sed -i -e 's/ -Werror=implicit-fallthrough//g' _builddir/build.ninja
ninja -C _builddir
ninja -C _builddir install
popd

pushd $SRC/qt
# Add the flags to Qt build, borrowed from qt
sed -i -e "s/QMAKE_CXXFLAGS    += -stdlib=libc++/QMAKE_CXXFLAGS    += -stdlib=libc++  $CXXFLAGS\nQMAKE_CFLAGS += $CFLAGS/g" qtbase/mkspecs/linux-clang-libc++/qmake.conf
sed -i -e "s/QMAKE_LFLAGS      += -stdlib=libc++/QMAKE_LFLAGS      += -stdlib=libc++ -lpthread $CXXFLAGS/g" qtbase/mkspecs/linux-clang-libc++/qmake.conf
# remove -fno-rtti which conflicts with -fsanitize=vptr when building with sanitizer undefined
sed -i -e "s/QMAKE_CXXFLAGS_RTTI_OFF    = -fno-rtti/QMAKE_CXXFLAGS_RTTI_OFF    = /g" qtbase/mkspecs/common/gcc-base.conf
MAKEFLAGS=-j$(nproc) $SRC/qt/configure -qt-libmd4c -platform linux-clang-libc++ -static -opensource -confirm-license -no-opengl -no-glib -nomake tests -nomake examples -prefix $PREFIX -D QT_NO_DEPRECATED_WARNINGS
make -j$(nproc) > /dev/null
make install
popd

# Poppler complains when PKG_CONFIG is set to `which pkg-config --static` so
# temporarily removing it
export PKG_CONFIG="`which pkg-config`"

mkdir -p $SRC/poppler/build
pushd $SRC/poppler/build
cmake .. \
  -DCMAKE_BUILD_TYPE=debug \
  -DBUILD_SHARED_LIBS=OFF \
  -DFONT_CONFIGURATION=generic \
  -DENABLE_FUZZER=OFF \
  -DENABLE_DCTDECODER=none \
  -DENABLE_GOBJECT_INTROSPECTION=OFF \
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
  -DCMAKE_INSTALL_PREFIX=$PREFIX \
  -DCMAKE_PREFIX_PATH=$PREFIX

export PKG_CONFIG="`which pkg-config` --static"
make -j$(nproc) poppler poppler-cpp poppler-glib poppler-qt5

PREDEPS_LDFLAGS="-Wl,-Bdynamic -ldl -lm -lc -lz -pthread -lrt -lpthread"
DEPS="gmodule-2.0 glib-2.0 gio-2.0 gobject-2.0 freetype2 lcms2 libopenjp2 libpng cairo cairo-gobject pango"
BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags $DEPS`"
BUILD_LDFLAGS="-Wl,-static `pkg-config --static --libs $DEPS`"

fuzzers=$(find $SRC/poppler/cpp/tests/fuzzing/ -name "*_fuzzer.cc")
for f in $fuzzers; do
  fuzzer_name=$(basename $f .cc)

  $CXX $CXXFLAGS -std=c++11 -I$SRC/poppler/cpp \
    $BUILD_CFLAGS \
    $f -o $OUT/$fuzzer_name \
    $PREDEPS_LDFLAGS \
    $SRC/poppler/build/cpp/libpoppler-cpp.a \
    $SRC/poppler/build/libpoppler.a \
    $BUILD_LDFLAGS \
    $LIB_FUZZING_ENGINE \
    -Wl,-Bdynamic
done

fuzzers=$(find $SRC/poppler/glib/tests/fuzzing/ -name "*_fuzzer.cc")
for f in $fuzzers; do
  fuzzer_name=$(basename $f .cc)

  $CXX $CXXFLAGS -std=c++11 -I$SRC/poppler/glib -I$SRC/poppler/build/glib \
    $BUILD_CFLAGS \
    $f -o $OUT/$fuzzer_name \
    $PREDEPS_LDFLAGS \
    $SRC/poppler/build/glib/libpoppler-glib.a \
    $SRC/poppler/build/cpp/libpoppler-cpp.a \
    $SRC/poppler/build/libpoppler.a \
    $BUILD_LDFLAGS \
    $LIB_FUZZING_ENGINE \
    -Wl,-Bdynamic
done

PREDEPS_LDFLAGS="-Wl,-Bdynamic -ldl -lm -lc -lz -pthread -lrt -lpthread"
DEPS="gmodule-2.0 glib-2.0 gio-2.0 gobject-2.0 freetype2 lcms2 libopenjp2 libpng Qt5Core Qt5Gui Qt5Xml"
BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags $DEPS`"
BUILD_LDFLAGS="-Wl,-static `pkg-config --static --libs $DEPS`"

fuzzers=$(find $SRC/poppler/qt5/tests/fuzzing/ -name "*_fuzzer.cc")
for f in $fuzzers; do
  fuzzer_name=$(basename $f .cc)

  $CXX $CXXFLAGS -std=c++11 -fPIC \
    -I$SRC/poppler/qt5/src \
    $BUILD_CFLAGS \
    $f -o $OUT/$fuzzer_name \
    $PREDEPS_LDFLAGS \
    $SRC/poppler/build/qt5/src/libpoppler-qt5.a \
    $SRC/poppler/build/cpp/libpoppler-cpp.a \
    $SRC/poppler/build/libpoppler.a \
    $BUILD_LDFLAGS \
    $LIB_FUZZING_ENGINE \
    -Wl,-Bdynamic
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
  ln -sf $OUT/poppler_seed_corpus.zip $OUT/${fuzzer_name}_seed_corpus.zip
  ln -sf $OUT/poppler.dict $OUT/${fuzzer_name}.dict
done

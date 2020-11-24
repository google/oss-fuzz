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

pushd $WORK
tar xvJf $SRC/glib-2.64.2.tar.xz
cd glib-2.64.2
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

pushd $WORK
tar xvJf $SRC/pango-1.48.0.tar.xz
cd pango-1.48.0 
meson \
    -Ddefault_library=static \
    --prefix=$PREFIX \
    --libdir=lib \
    _builddir
sed -i -e 's/ -Werror=implicit-fallthrough//g' _builddir/build.ninja
ninja -C _builddir
ninja -C _builddir install

pushd $SRC/qtbase
sed -i -e "s/QMAKE_CXXFLAGS    += -stdlib=libc++/QMAKE_CXXFLAGS    += -stdlib=libc++  $CXXFLAGS\nQMAKE_CFLAGS += $CFLAGS/g" mkspecs/linux-clang-libc++/qmake.conf
sed -i -e "s/QMAKE_LFLAGS      += -stdlib=libc++/QMAKE_LFLAGS      += -stdlib=libc++ -lpthread $CXXFLAGS/g" mkspecs/linux-clang-libc++/qmake.conf
# make qmake compile faster
sed -i -e "s/MAKE\")/MAKE\" -j$(nproc))/g" configure
# add QT_NO_WARNING_OUTPUT to make the output a bit cleaner by not containing lots of QBuffer::seek: Invalid pos
sed -i -e "s/DEFINES += QT_NO_USING_NAMESPACE QT_NO_FOREACH/DEFINES += QT_NO_USING_NAMESPACE QT_NO_FOREACH QT_NO_WARNING_OUTPUT/g" src/corelib/corelib.pro
./configure --prefix="$PREFIX" --glib=no --libpng=qt -opensource -confirm-license -static -no-opengl -no-icu -platform linux-clang-libc++ -v
cd src
../bin/qmake -o Makefile src.pro
make sub-corelib sub-gui sub-xml -j$(nproc)
make install

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
  -DCMAKE_INSTALL_PREFIX=$PREFIX
  #-DQt5Core_DIR=$SRC/qtbase/lib/cmake/Qt5Core/
  #-DCMAKE_INSTALL_PREFIX=$WORK

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
    #$WORK/lib/libfreetype.a \
    #$WORK/lib/liblcms2.a \
    #$WORK/lib/libopenjp2.a \
    #$WORK/lib/libpng.a \
    #$WORK/lib/libz.a

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
    #-I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
    #-I/usr/include/cairo \
    #$WORK/lib/libfreetype.a \
    #$WORK/lib/liblcms2.a \
    #$WORK/lib/libopenjp2.a \
    #$WORK/lib/libpng.a \
    #$WORK/lib/libz.a \
    #$SRC/pango-1.48.0/_build/pango/libpango-1.0.a \
    #-Wl,-Bstatic -lgmodule-2.0 -lgio-2.0 -lgobject-2.0 -lglib-2.0 -lcairo-gobject -lcairo \

#PREDEPS_LDFLAGS="-Wl,-Bdynamic -ldl -lm -lc -lz -pthread -lrt -lpthread -lQt5Core -lQt5Gui -lQt5Xml"
PREDEPS_LDFLAGS="-Wl,-Bdynamic -ldl -lm -lc -lz -pthread -lrt -lpthread"
#DEPS="gmodule-2.0 glib-2.0 gio-2.0 gobject-2.0 freetype2 lcms2 libopenjp2 libpng" 
DEPS="gmodule-2.0 glib-2.0 gio-2.0 gobject-2.0 freetype2 lcms2 libopenjp2 libpng Qt5Core Qt5Gui Qt5Xml"
BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags $DEPS`"
BUILD_LDFLAGS="-Wl,-static `pkg-config --static --libs $DEPS`"
QT_LDFLAGS="-lQt5Core -lQt5Gui -lQt5Xml"

#mkdir -p $OUT/lib
#cp /usr/lib/x86_64-linux-gnu/libQt5Core.so.5 $OUT/lib
#cp /usr/lib/x86_64-linux-gnu/libQt5Gui.so.5 $OUT/lib
#cp /usr/lib/x86_64-linux-gnu/libQt5Xml.so.5 $OUT/lib

fuzzers=$(find $SRC/poppler/qt5/tests/fuzzing/ -name "*_fuzzer.cc")

for f in $fuzzers; do
  fuzzer_name=$(basename $f .cc)

  $CXX $CXXFLAGS -std=c++11 -fPIC \
    -I/usr/include/x86_64-linux-gnu/qt5 -I$SRC/poppler/qt5/src \
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

#-Wl,-rpath,'$ORIGIN/lib' $QT_LDFLAGS \
#find $OUT -type f -executable -name "qt_*" -exec patchelf --set-rpath '$ORIGIN/lib' {} \;

    #$WORK/lib/libfreetype.a \
    #$WORK/lib/liblcms2.a \
    #$WORK/lib/libopenjp2.a \
    #$WORK/lib/libpng.a \
    #$WORK/lib/libz.a \
    #-Wl,-Bstatic -lQt5Gui -lQt5Core -lQt5Xml

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

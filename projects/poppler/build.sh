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

# Install Boost headers
cd $SRC/
tar jxf boost_1_76_0.tar.bz2
cd boost_1_76_0/
CFLAGS="" CXXFLAGS="" ./bootstrap.sh
CFLAGS="" CXXFLAGS="" ./b2 headers
cp -R boost/ /usr/include/

pushd $SRC/zlib
CFLAGS=-fPIC ./configure --static --prefix=$PREFIX
make install -j$(nproc)

pushd $SRC
tar zxf nss-3.75-with-nspr-4.32.tar.gz
cd nss-3.75
nss_flag=""
SAVE_CFLAGS="$CFLAGS"
SAVE_CXXFLAGS="$CXXFLAGS"
if [ "$SANITIZER" = "memory" ]; then
    nss_flag="--msan"
elif [ "$SANITIZER" = "address" ]; then
    nss_flag="--asan"
elif [ "$SANITIZER" = "undefined" ]; then
    nss_flag="--ubsan"
elif [ "$SANITIZER" = "coverage" ]; then
    # some parts of nss don't like -fcoverage-mapping nor -fprofile-instr-generate :/
    CFLAGS="${CFLAGS/"-fcoverage-mapping"/" "}"
    CFLAGS="${CFLAGS/"-fprofile-instr-generate"/" "}"
    CXXFLAGS="${CXXFLAGS/"-fcoverage-mapping"/" "}"
    CXXFLAGS="${CXXFLAGS/"-fprofile-instr-generate"/" "}"
fi

./nss/build.sh $nss_flag --disable-tests --static -v -Dmozilla_client=1 -Dzlib_libs=$PREFIX/lib/libz.a -Dsign_libs=0

CFLAGS="$SAVE_CFLAGS"
CXXFLAGS="$SAVE_CXXFLAGS"

# NSS has a .pc.in file but doesn't do anything with it
cp nss/pkg/pkg-config/nss.pc.in $PREFIX/lib/pkgconfig/nss.pc
sed -i "s#\${libdir}#${SRC}/nss-3.75/dist/Debug/lib#g" $PREFIX/lib/pkgconfig/nss.pc
sed -i "s#\${includedir}#${SRC}/nss-3.75/dist/public/nss#g" $PREFIX/lib/pkgconfig/nss.pc
sed -i "s#%NSS_VERSION%#3.75#g" $PREFIX/lib/pkgconfig/nss.pc
cp dist/Debug/lib/pkgconfig/nspr.pc $PREFIX/lib/pkgconfig/

pushd $SRC/freetype
./autogen.sh
./configure --prefix="$PREFIX" --disable-shared PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
make -j$(nproc)
make install

pushd $SRC/Little-CMS
./autogen.sh --prefix="$PREFIX" --disable-shared PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
make -j$(nproc)
make install

mkdir -p $SRC/openjpeg/build
pushd $SRC/openjpeg/build
sed -i "s#\${LCMS_LIBNAME}#-L$PREFIX/lib \${LCMS_LIBNAME}#" ../src/bin/jp2/CMakeLists.txt
PKG_CONFIG=`which pkg-config` cmake .. -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=$PREFIX
make -j$(nproc) install

if [ "$SANITIZER" != "memory" ]; then

    pushd $SRC/fontconfig
    meson \
        --prefix=$PREFIX \
        --libdir=lib \
        --default-library=static \
        _builddir
    ninja -C _builddir
    ninja -C _builddir install
    popd

    pushd $SRC/glib-2.70.0
    # remove once there's a released glib that contains https://gitlab.gnome.org/GNOME/glib/-/merge_requests/2324
    sed -i s#https://ftp.pcre.org/pub/pcre/pcre-8.37.tar.bz2#https://sourceforge.net/projects/pcre/files/pcre/8.37/pcre-8.37.tar.bz2# subprojects/libpcre.wrap
    meson \
        --prefix=$PREFIX \
        --libdir=lib \
        --default-library=static \
        -Db_lundef=false \
        -Doss_fuzz=enabled \
        -Dlibmount=disabled \
        _builddir
    ninja -C _builddir
    ninja -C _builddir install
    popd

    pushd $SRC/libpng
    autoreconf -fi
    CPPFLAGS=-I$PREFIX/include LDFLAGS=-L$PREFIX/lib ./configure --prefix="$PREFIX" --disable-shared --disable-dependency-tracking
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

    pushd $SRC/pango
    CFLAGS="$CFLAGS -fno-sanitize=vptr" CXXFLAGS="$CXXFLAGS -fno-sanitize=vptr" meson \
        -Ddefault_library=static \
        --prefix=$PREFIX \
        --libdir=lib \
        _builddir
    sed -i -e 's/ -Werror=implicit-fallthrough//g' _builddir/build.ninja
    ninja -C _builddir
    ninja -C _builddir install
    popd
fi

pushd $SRC/qtbase
# add the flags to Qt build too
sed -i -e "s/QMAKE_CXXFLAGS    += -stdlib=libc++/QMAKE_CXXFLAGS    += -stdlib=libc++  $CXXFLAGS\nQMAKE_CFLAGS += $CFLAGS/g" mkspecs/linux-clang-libc++/qmake.conf
sed -i -e "s/QMAKE_LFLAGS      += -stdlib=libc++/QMAKE_LFLAGS      += -stdlib=libc++ -lpthread $CXXFLAGS/g" mkspecs/linux-clang-libc++/qmake.conf
# disable sanitize=vptr for harfbuzz since it compiles without rtti
sed -i -e "s/TARGET = qtharfbuzz/TARGET = qtharfbuzz\nQMAKE_CXXFLAGS += -fno-sanitize=vptr/g" src/3rdparty/harfbuzz-ng/harfbuzz-ng.pro
# make qmake compile faster
sed -i -e "s/MAKE\")/MAKE\" -j$(nproc))/g" configure
# Fix memory stuff in qt 5.15 unfixable since branch is closed now
sed -i -e "s/struct statx statxBuffer/struct statx statxBuffer = {}/g" src/corelib/io/qfilesystemengine_unix.cpp
./configure --glib=no --libpng=qt -opensource -confirm-license -static -no-opengl -no-icu -no-pkg-config -platform linux-clang-libc++ -nomake tests -nomake examples -prefix $PREFIX -D QT_NO_DEPRECATED_WARNINGS
make -j$(nproc)
make install
popd

# Poppler complains when PKG_CONFIG is set to `which pkg-config --static` so
# temporarily removing it
export PKG_CONFIG="`which pkg-config`"

if [ "$SANITIZER" != "memory" ]; then
    POPPLER_ENABLE_GLIB=ON
    POPPLER_FONT_CONFIGURATION=fontconfig
else
    POPPLER_ENABLE_GLIB=OFF
    POPPLER_FONT_CONFIGURATION=generic
fi

mkdir -p $SRC/poppler/build
pushd $SRC/poppler/build
cmake .. \
  -DCMAKE_BUILD_TYPE=debug \
  -DBUILD_SHARED_LIBS=OFF \
  -DENABLE_FUZZER=OFF \
  -DFONT_CONFIGURATION=$POPPLER_FONT_CONFIGURATION \
  -DENABLE_DCTDECODER=none \
  -DENABLE_GOBJECT_INTROSPECTION=OFF \
  -DENABLE_LIBPNG=OFF \
  -DENABLE_ZLIB=OFF \
  -DENABLE_LIBTIFF=OFF \
  -DENABLE_LIBJPEG=OFF \
  -DENABLE_GLIB=$POPPLER_ENABLE_GLIB \
  -DENABLE_LIBCURL=OFF \
  -DENABLE_QT5=ON \
  -DENABLE_UTILS=OFF \
  -DWITH_Cairo=$POPPLER_ENABLE_GLIB \
  -DCMAKE_INSTALL_PREFIX=$PREFIX

export PKG_CONFIG="`which pkg-config` --static"
make -j$(nproc) poppler poppler-cpp poppler-qt5
if [ "$SANITIZER" != "memory" ]; then
    make -j$(nproc) poppler-glib
fi

PREDEPS_LDFLAGS="-Wl,-Bdynamic -ldl -lm -lc -lz -pthread -lrt -lpthread"
DEPS="freetype2 lcms2 libopenjp2"
if [ "$SANITIZER" != "memory" ]; then
    DEPS="$DEPS fontconfig libpng"
fi
BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags $DEPS`"
BUILD_LDFLAGS="-Wl,-static `pkg-config --static --libs $DEPS`"
# static linking is hard ^_^
NSS_STATIC_LIBS=`ls $SRC/nss-3.75/dist/Debug/lib/lib*.a`
NSS_STATIC_LIBS="$NSS_STATIC_LIBS $NSS_STATIC_LIBS $NSS_STATIC_LIBS"
BUILD_LDFLAGS="$BUILD_LDFLAGS $NSS_STATIC_LIBS"

fuzzers=$(find $SRC/poppler/cpp/tests/fuzzing/ -name "*_fuzzer.cc")

for f in $fuzzers; do
    fuzzer_name=$(basename $f .cc)

    $CXX $CXXFLAGS -std=c++11 -I$SRC/poppler/cpp -I$SRC/poppler/build/cpp \
        $BUILD_CFLAGS \
        $f -o $OUT/$fuzzer_name \
        $PREDEPS_LDFLAGS \
        $SRC/poppler/build/cpp/libpoppler-cpp.a \
        $SRC/poppler/build/libpoppler.a \
        $BUILD_LDFLAGS \
        $LIB_FUZZING_ENGINE \
        $LIB_FUZZING_ENGINE \
        -Wl,-Bdynamic
done

if [ "$SANITIZER" != "memory" ]; then
    DEPS="gmodule-2.0 glib-2.0 gio-2.0 gobject-2.0 freetype2 lcms2 libopenjp2 cairo cairo-gobject pango fontconfig libpng"
    BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags $DEPS`"
    BUILD_LDFLAGS="-Wl,-static `pkg-config --static --libs $DEPS`"
    BUILD_LDFLAGS="$BUILD_LDFLAGS $NSS_STATIC_LIBS"

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
fi

PREDEPS_LDFLAGS="-Wl,-Bdynamic -ldl -lm -lc -lz -pthread -lrt -lpthread"
DEPS="freetype2 lcms2 libopenjp2 Qt5Core Qt5Gui Qt5Xml"
if [ "$SANITIZER" != "memory" ]; then
    DEPS="$DEPS fontconfig libpng"
fi
BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags $DEPS`"
BUILD_LDFLAGS="-Wl,-static `pkg-config --static --libs $DEPS`"
BUILD_LDFLAGS="$BUILD_LDFLAGS $NSS_STATIC_LIBS"

fuzzers=$(find $SRC/poppler/qt5/tests/fuzzing/ -name "*_fuzzer.cc")
for f in $fuzzers; do
    fuzzer_name=$(basename $f .cc)

    $CXX $CXXFLAGS -std=c++11 -fPIC \
        -I$SRC/poppler/qt5/src -I$SRC/poppler/build/qt5/src \
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

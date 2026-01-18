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

# Temporarily Add -D_GNU_SOURCE to CFLAGS to fix freetype's dependence on GNU
# extensions for dlsym to dynamically load harfbuzz. This feature
# should potentially be disabled instead of fixing the compilation. But that is
# not possible to do from the OSS-Fuzz repo :-)
# See https://github.com/google/oss-fuzz/pull/13325 for more details.
export CFLAGS="$CFLAGS -D_GNU_SOURCE"

# Install Boost headers
cd $SRC/
tar jxf boost_1_87_0.tar.bz2
cd boost_1_87_0/
CFLAGS="" CXXFLAGS="" ./bootstrap.sh
CFLAGS="" CXXFLAGS="" ./b2 headers
./b2 --with-math install

pushd $SRC/zlib
mkdir build && cd build
CFLAGS=-fPIC ../configure --static --prefix=$PREFIX
make install -j$(nproc)

pushd $SRC
tar zxf nss-3.99-with-nspr-4.35.tar.gz
cd nss-3.99
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
sed -i "s#\${libdir}#${SRC}/nss-3.99/dist/Debug/lib#g" $PREFIX/lib/pkgconfig/nss.pc
sed -i "s#\${includedir}#${SRC}/nss-3.99/dist/public/nss#g" $PREFIX/lib/pkgconfig/nss.pc
sed -i "s#%NSS_VERSION%#3.99#g" $PREFIX/lib/pkgconfig/nss.pc
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

    pushd $SRC/glib-2.80.0
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
    sed -i -e 's/#pragma GCC diagnostic error   "-Wcast-function-type"//g' subprojects/harfbuzz/src/hb.hh
    ninja -C _builddir
    ninja -C _builddir install
    popd
fi

QT6_LDFLAGS=""
if [[ $FUZZING_ENGINE == "afl" ]]; then
    QT6_LDFLAGS="-fuse-ld=lld"
fi
pushd $SRC/qtbase
LDFLAGS="$QT6_LDFLAGS" ./configure -no-glib -no-dbus -qt-harfbuzz -qt-pcre -qt-libpng -opensource -confirm-license -static -no-opengl -no-icu \
    -platform linux-clang-libc++ -debug -prefix $PREFIX -I $PREFIX/include/ -L $PREFIX/lib/
ninja install -j$(nproc)
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
  -DENABLE_GPGME=OFF \
  -DENABLE_QT6=ON \
  -DENABLE_QT5=OFF \
  -DENABLE_UTILS=OFF \
  -DWITH_Cairo=$POPPLER_ENABLE_GLIB \
  -DCMAKE_INSTALL_PREFIX=$PREFIX

export PKG_CONFIG="`which pkg-config` --static"
make -j$(nproc) poppler poppler-cpp poppler-qt6
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
NSS_STATIC_LIBS=`ls $SRC/nss-3.99/dist/Debug/lib/lib*.a`
NSS_STATIC_LIBS="$NSS_STATIC_LIBS $NSS_STATIC_LIBS $NSS_STATIC_LIBS"
BUILD_LDFLAGS="$BUILD_LDFLAGS $NSS_STATIC_LIBS"

fuzzers=$(find $SRC/poppler/cpp/tests/fuzzing/ -name "*_fuzzer.cc")

for f in $fuzzers; do
    fuzzer_name=$(basename $f .cc)

    $CXX $CXXFLAGS -std=c++23 -I$SRC/poppler/cpp -I$SRC/poppler/build/cpp \
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

        $CXX $CXXFLAGS -std=c++23 -I$SRC/poppler/glib -I$SRC/poppler/build/glib \
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
DEPS="freetype2 lcms2 libopenjp2"
if [ "$SANITIZER" != "memory" ]; then
    DEPS="$DEPS fontconfig"
fi
BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags $DEPS`"
BUILD_LDFLAGS="-Wl,-static `pkg-config --static --libs $DEPS`"
QT6_STATIC_LIBS="$PREFIX/lib/libQt6Gui.a $PREFIX/lib/libQt6Xml.a $PREFIX/lib/libQt6Core.a $PREFIX/lib/libQt6BundledHarfbuzz.a $PREFIX/lib/libQt6BundledLibpng.a $PREFIX/lib/libQt6BundledPcre2.a $PREFIX/lib/libz.a"
BUILD_LDFLAGS="$BUILD_LDFLAGS $QT6_STATIC_LIBS $NSS_STATIC_LIBS"

fuzzers=$(find $SRC/poppler/qt6/tests/fuzzing/ -name "*_fuzzer.cc")
for f in $fuzzers; do
    fuzzer_name=$(basename $f .cc)

    $CXX $CXXFLAGS -std=c++23 -fPIC \
        -I$SRC/poppler/qt6/src -I$SRC/poppler/build/qt6/src \
        $BUILD_CFLAGS \
        $f -o $OUT/$fuzzer_name \
        $PREDEPS_LDFLAGS \
        $QT6_LDFLAGS \
        $SRC/poppler/build/qt6/src/libpoppler-qt6.a \
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

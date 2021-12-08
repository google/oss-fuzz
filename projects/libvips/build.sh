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

export PKG_CONFIG_PATH=/work/lib/pkgconfig
export LDFLAGS="$CXXFLAGS"

# libz
pushd $SRC/zlib
./configure --static --prefix=$WORK
make -j$(nproc) all
make install
popd

# libexif
pushd $SRC/libexif
autoreconf -fi
./configure \
  --enable-static \
  --disable-shared \
  --disable-docs \
  --disable-dependency-tracking \
  --prefix=$WORK
make -j$(nproc)
make install
popd

# lcms
pushd $SRC/lcms
./autogen.sh
./configure \
  --enable-static \
  --disable-shared \
  --disable-dependency-tracking \
  --prefix=$WORK
make -j$(nproc)
make install
popd

# aom
pushd $SRC/aom
mkdir -p build/linux
cd build/linux
cmake -G "Unix Makefiles" \
  -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_INSTALL_PREFIX=$WORK -DCMAKE_INSTALL_LIBDIR=lib \
  -DENABLE_SHARED=FALSE -DCONFIG_PIC=1 \
  -DENABLE_EXAMPLES=0 -DENABLE_DOCS=0 -DENABLE_TESTS=0 \
  -DCONFIG_SIZE_LIMIT=1 \
  -DDECODE_HEIGHT_LIMIT=12288 -DDECODE_WIDTH_LIMIT=12288 \
  -DDO_RANGE_CHECK_CLAMP=1 \
  -DAOM_MAX_ALLOCABLE_MEMORY=536870912 \
  -DAOM_TARGET_CPU=generic \
  ../../
make clean
make -j$(nproc)
make install
popd

# libheif
pushd $SRC/libheif
autoreconf -fi
./configure \
  --disable-shared \
  --enable-static \
  --disable-examples \
  --disable-go \
  --prefix=$WORK \
  CPPFLAGS=-I$WORK/include
make clean
make -j$(nproc)
make install
popd

# libjpeg-turbo
pushd $SRC/libjpeg-turbo
cmake . -DCMAKE_INSTALL_PREFIX=$WORK -DENABLE_STATIC=TRUE -DENABLE_SHARED=FALSE -DWITH_TURBOJPEG=FALSE
make -j$(nproc)
make install
popd

# libpng
pushd $SRC/libpng
sed -ie "s/option WARNING /& disabled/" scripts/pnglibconf.dfa
autoreconf -fi
./configure \
  --prefix=$WORK \
  --disable-shared \
  --disable-dependency-tracking
make -j$(nproc)
make install
popd

# libspng
pushd $SRC/libspng
cmake . -DCMAKE_INSTALL_PREFIX=$WORK -DSPNG_STATIC=TRUE -DSPNG_SHARED=FALSE -DZLIB_ROOT=$WORK
make -j$(nproc)
make install
# Fix pkg-config file of libspng
sed -i'.bak' "s/-lspng/&_static/" $WORK/lib/pkgconfig/libspng.pc
popd

# libwebp
pushd $SRC/libwebp
autoreconf -fi
./configure \
  --enable-libwebpdemux \
  --enable-libwebpmux \
  --disable-shared \
  --disable-jpeg \
  --disable-tiff \
  --disable-gif \
  --disable-wic \
  --disable-threading \
  --disable-dependency-tracking \
  --prefix=$WORK
make -j$(nproc)
make install
popd

# libtiff ... a bug in libtiff master as of 20 Nov 2019 means we have to 
# explicitly disable lzma
pushd $SRC/libtiff
autoreconf -fi
./configure \
  --disable-lzma \
  --disable-shared \
  --disable-dependency-tracking \
  --prefix=$WORK
make -j$(nproc)
make install
popd

# jpeg-xl (libjxl)
pushd $SRC/libjxl
# FIXME: Remove the `-DHWY_DISABLED_TARGETS=HWY_SSSE3` workaround, see:
# https://github.com/libjxl/libjxl/issues/858
cmake -G "Unix Makefiles" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=$CC \
  -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_C_FLAGS="$CFLAGS -DHWY_DISABLED_TARGETS=HWY_SSSE3" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS -DHWY_DISABLED_TARGETS=HWY_SSSE3" \
  -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" \
  -DCMAKE_MODULE_LINKER_FLAGS="$LDFLAGS" \
  -DCMAKE_INSTALL_PREFIX="$WORK" \
  -DCMAKE_THREAD_LIBS_INIT="-lpthread" \
  -DCMAKE_USE_PTHREADS_INIT=1 \
  -DBUILD_SHARED_LIBS=0 \
  -DBUILD_TESTING=0 \
  -DJPEGXL_FORCE_SYSTEM_BROTLI=1 \
  -DJPEGXL_ENABLE_FUZZERS=0 \
  -DJPEGXL_ENABLE_TOOLS=0 \
  -DJPEGXL_ENABLE_MANPAGES=0 \
  -DJPEGXL_ENABLE_BENCHMARK=0 \
  -DJPEGXL_ENABLE_EXAMPLES=0 \
  -DJPEGXL_ENABLE_SKCMS=0 \
  -DJPEGXL_ENABLE_SJPEG=0 \
  .
make -j$(nproc)
make install
popd

# libimagequant
pushd $SRC/libimagequant
meson setup --prefix=$WORK --libdir=lib --default-library=static build
cd build
ninja -j$(nproc)
ninja install
popd

# cgif
pushd $SRC/cgif
meson setup --prefix=$WORK --libdir=lib --default-library=static build
cd build
ninja -j$(nproc)
ninja install
popd

# libvips
sed -i'.bak' "/test/d" Makefile.am
sed -i'.bak' "/tools/d" Makefile.am
PKG_CONFIG="pkg-config --static" ./autogen.sh \
  --disable-shared \
  --disable-modules \
  --disable-gtk-doc \
  --disable-gtk-doc-html \
  --disable-dependency-tracking \
  --prefix=$WORK
make -j$(nproc) CCLD=$CXX
make install

# Merge the seed corpus in a single directory, exclude files larger than 2k
mkdir -p fuzz/corpus
find \
  $SRC/afl-testcases/{gif*,jpeg*,png,tiff,webp}/full/images \
  fuzz/*_fuzzer_corpus \
  test/test-suite/images \
  -type f -size -2k \
  -exec bash -c 'hash=($(sha1sum {})); mv {} fuzz/corpus/$hash' ';'
zip -jrq $OUT/seed_corpus.zip fuzz/corpus

# Build fuzzers and link corpus
for fuzzer in fuzz/*_fuzzer.cc; do
  target=$(basename "$fuzzer" .cc)
  $CXX $CXXFLAGS -std=c++11 "$fuzzer" -o "$OUT/$target" \
    -I$WORK/include \
    -I/usr/include/glib-2.0 \
    -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
    $WORK/lib/libvips.a \
    $WORK/lib/libexif.a \
    $WORK/lib/liblcms2.a \
    $WORK/lib/libjpeg.a \
    $WORK/lib/libpng.a \
    $WORK/lib/libspng_static.a \
    $WORK/lib/libz.a \
    $WORK/lib/libwebpmux.a \
    $WORK/lib/libwebpdemux.a \
    $WORK/lib/libwebp.a \
    $WORK/lib/libtiff.a \
    $WORK/lib/libheif.a \
    $WORK/lib/libaom.a \
    $WORK/lib/libjxl.a \
    $WORK/lib/libjxl_threads.a \
    $WORK/lib/libhwy.a \
    $WORK/lib/libimagequant.a \
    $WORK/lib/libcgif.a \
    $LIB_FUZZING_ENGINE \
    -Wl,-Bstatic \
    -lfftw3 -lexpat -lbrotlienc -lbrotlidec -lbrotlicommon \
    -lgmodule-2.0 -lgio-2.0 -lgobject-2.0 -lffi -lglib-2.0 \
    -lresolv -lmount -lblkid -lselinux -lsepol -lpcre \
    -Wl,-Bdynamic -pthread
  ln -sf "seed_corpus.zip" "$OUT/${target}_seed_corpus.zip"
done

# Copy options and dictionary files to $OUT
find fuzz -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
find fuzz -name '*_fuzzer.options' -exec cp -v '{}' $OUT ';'

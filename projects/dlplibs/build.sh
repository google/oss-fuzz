#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

# HACK to force linking with static icu and libxml2
mkdir static
cp -pL \
    /usr/lib/*/libicu*.a \
    /usr/lib/*/libxml2.a \
    /usr/lib/*/liblzma.a \
    static
staticlib=$(pwd)/static

tar -xJf $SRC/zlib-1.2.11.tar.xz
pushd zlib-1.2.11
./configure --static
make -j$(nproc)
export ZLIB_CFLAGS="-I$(pwd)"
export ZLIB_LIBS="-L$(pwd) -lz"
popd

tar -xzf $SRC/lcms2-2.8.tar.gz
pushd lcms2-2.8
./configure --disable-shared --enable-static --without-jpeg --without-tiff
make -C src -j$(nproc)
export LCMS2_CFLAGS="-I$(pwd)/include"
export LCMS2_LIBS="-L$(pwd)/src -llcms2"
popd

tar -xJf $SRC/libpng-1.6.34.tar.xz
pushd libpng-1.6.34
./configure --disable-shared --enable-static
make -j$(nproc)
export LIBPNG_CFLAGS="-I$(pwd)"
export LIBPNG_LIBS="-L$(pwd) -lpng16"
popd

pushd librevenge
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tests --enable-fuzzers
make -j$(nproc)
rvnginc=$(pwd)/inc
rvnglib=$(pwd)/src/lib
export REVENGE_CFLAGS="-I$(pwd)/inc"
export REVENGE_LIBS="-L$(pwd)/src/lib -lrevenge-0.0"
export REVENGE_STREAM_CFLAGS="-I$(pwd)/inc"
export REVENGE_STREAM_LIBS="-L$(pwd)/src/lib -lrevenge-stream-0.0"
export REVENGE_GENERATORS_CFLAGS="-I$(pwd)/inc"
export REVENGE_GENERATORS_LIBS="-L$(pwd)/src/lib -lrevenge-generators-0.0"
popd

pushd libmspub
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers \
    ICU_CFLAGS="$(pkg-config --cflags icu-i18n)" \
    ICU_LIBS="-L$staticlib $(pkg-config --libs icu-i18n)"
make -j$(nproc)
popd

pushd libcdr
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers \
    ICU_CFLAGS="$(pkg-config --cflags icu-i18n)" \
    ICU_LIBS="-L$staticlib $(pkg-config --libs icu-i18n)"
make -j$(nproc)
popd

pushd libvisio
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers \
    LDFLAGS=-L$staticlib \
    LIBXML_LIBS="-lxml2 -llzma"
make -j$(nproc)
popd

pushd libzmf
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers \
    LDFLAGS=-L$staticlib
make -j$(nproc)
popd

pushd libpagemaker
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers
make -j$(nproc)
popd

pushd libfreehand
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers \
    LDFLAGS=-L$staticlib
make -j$(nproc)
popd

pushd libwpd
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers
make -j$(nproc)
export WPD_CFLAGS=-I$(pwd)/inc
export WPD_LIBS="-L$(pwd)/src/lib -lwpd-0.10"
popd

pushd libwpg
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers
make -j$(nproc)
popd

pushd libstaroffice
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers
make -j$(nproc)
popd

pushd libwps
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers
make -j$(nproc)
popd

pushd libmwaw
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --disable-zip --enable-fuzzers \
    REVENGE_LIBS="$REVENGE_LIBS $REVENGE_STREAM_LIBS"
make -C src/lib -j$(nproc)
# Link with less parallelism to avoid memory problems on the builders
make -j2
popd

pushd libe-book
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --without-tools --enable-fuzzers --without-liblangtag \
    LDFLAGS=-L$staticlib \
    XML_LIBS="-lxml2 -llzma"
make -j$(nproc)
popd

pushd libabw
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers \
    LDFLAGS=-L$staticlib \
    LIBXML_LIBS="-lxml2 -llzma -licuuc -licudata"
make -j$(nproc)
popd

pushd libetonyek
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static \
    --without-tools --enable-fuzzers --with-mdds=0.x --without-liblangtag \
    LDFLAGS=-L$staticlib \
    XML_LIBS="-lxml2 -llzma -licuuc -licudata"
make -j$(nproc)
popd

pushd libqxp
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers \
    LDFLAGS=-L$staticlib
make -j$(nproc)
popd

cp */src/fuzz/*fuzzer $OUT
cp */src/fuzz/*.dict $OUT
cp *_seed_corpus.zip $OUT
cp *.options $OUT
cp *.dict $OUT

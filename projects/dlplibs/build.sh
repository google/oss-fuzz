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

# HACK to force linking with static icu, libxml2 and liblangtag
# WTH is liblangtag linked with glib?!
mkdir static
cp -pL \
    /usr/lib/*/libicu*.a \
    /usr/lib/*/libxml2.a \
    /usr/lib/*/liblzma.a \
    /usr/lib/*/libpng*.a \
    /usr/lib/*/liblangtag.a \
    /usr/lib/*/libglib-2.0.a \
    /usr/lib/*/libpcre.a \
    static
staticlib=$(pwd)/static

tar -xzf $SRC/lcms2-2.8.tar.gz
pushd lcms2-2.8
./configure --disable-shared --enable-static --without-jpeg --without-tiff
make -C src -j$(nproc)
lcmsinc=$(pwd)/include
lcmslib=$(pwd)/src
popd

pushd librevenge
./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tests --enable-fuzzers
make -j$(nproc)
rvnginc=$(pwd)/inc
rvnglib=$(pwd)/src/lib
popd

pushd libmspub
./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tools --enable-fuzzers \
    ICU_CFLAGS="$(pkg-config --cflags icu-i18n)" \
    ICU_LIBS="-L$staticlib $(pkg-config --libs icu-i18n)" \
    REVENGE_CFLAGS=-I$rvnginc REVENGE_LIBS="-L$rvnglib -lrevenge-0.0" \
    REVENGE_STREAM_CFLAGS=-I$rvnginc REVENGE_STREAM_LIBS="-L$rvnglib -lrevenge-stream-0.0" \
    REVENGE_GENERATORS_CFLAGS=-I$rvnginc REVENGE_GENERATORS_LIBS="-L$rvnglib -lrevenge-generators-0.0"
make -j$(nproc)
popd

pushd libcdr
./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tools --enable-fuzzers \
    ICU_CFLAGS="$(pkg-config --cflags icu-i18n)" \
    ICU_LIBS="-L$staticlib $(pkg-config --libs icu-i18n)" \
    LCMS2_CFLAGS=-I$lcmsinc LCMS2_LIBS="-L$lcmslib -llcms2" \
    REVENGE_CFLAGS=-I$rvnginc REVENGE_LIBS="-L$rvnglib -lrevenge-0.0" \
    REVENGE_STREAM_CFLAGS=-I$rvnginc REVENGE_STREAM_LIBS="-L$rvnglib -lrevenge-stream-0.0" \
    REVENGE_GENERATORS_CFLAGS=-I$rvnginc REVENGE_GENERATORS_LIBS="-L$rvnglib -lrevenge-generators-0.0"
make -j$(nproc)
popd

pushd libvisio
./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tools --enable-fuzzers \
    LDFLAGS=-L$staticlib \
    LIBXML_LIBS="-lxml2 -llzma" \
    REVENGE_CFLAGS=-I$rvnginc REVENGE_LIBS="-L$rvnglib -lrevenge-0.0" \
    REVENGE_STREAM_CFLAGS=-I$rvnginc REVENGE_STREAM_LIBS="-L$rvnglib -lrevenge-stream-0.0" \
    REVENGE_GENERATORS_CFLAGS=-I$rvnginc REVENGE_GENERATORS_LIBS="-L$rvnglib -lrevenge-generators-0.0"
make -j$(nproc)
popd

pushd libzmf
./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tools --enable-fuzzers \
    LDFLAGS=-L$staticlib \
    REVENGE_CFLAGS=-I$rvnginc REVENGE_LIBS="-L$rvnglib -lrevenge-0.0" \
    REVENGE_STREAM_CFLAGS=-I$rvnginc REVENGE_STREAM_LIBS="-L$rvnglib -lrevenge-stream-0.0" \
    REVENGE_GENERATORS_CFLAGS=-I$rvnginc REVENGE_GENERATORS_LIBS="-L$rvnglib -lrevenge-generators-0.0"
make -j$(nproc)
popd

pushd libpagemaker
./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tools --enable-fuzzers \
    REVENGE_CFLAGS=-I$rvnginc REVENGE_LIBS="-L$rvnglib -lrevenge-0.0" \
    REVENGE_STREAM_CFLAGS=-I$rvnginc REVENGE_STREAM_LIBS="-L$rvnglib -lrevenge-stream-0.0" \
    REVENGE_GENERATORS_CFLAGS=-I$rvnginc REVENGE_GENERATORS_LIBS="-L$rvnglib -lrevenge-generators-0.0"
make -j$(nproc)
popd

pushd libfreehand
./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tools --enable-fuzzers \
    LDFLAGS=-L$staticlib \
    LCMS2_CFLAGS=-I$lcmsinc LCMS2_LIBS="-L$lcmslib -llcms2" \
    REVENGE_CFLAGS=-I$rvnginc REVENGE_LIBS="-L$rvnglib -lrevenge-0.0" \
    REVENGE_STREAM_CFLAGS=-I$rvnginc REVENGE_STREAM_LIBS="-L$rvnglib -lrevenge-stream-0.0" \
    REVENGE_GENERATORS_CFLAGS=-I$rvnginc REVENGE_GENERATORS_LIBS="-L$rvnglib -lrevenge-generators-0.0"
make -j$(nproc)
popd

pushd libwpd
./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tools --enable-fuzzers \
    REVENGE_CFLAGS=-I$rvnginc REVENGE_LIBS="-L$rvnglib -lrevenge-0.0" \
    REVENGE_STREAM_CFLAGS=-I$rvnginc REVENGE_STREAM_LIBS="-L$rvnglib -lrevenge-stream-0.0" \
    REVENGE_GENERATORS_CFLAGS=-I$rvnginc REVENGE_GENERATORS_LIBS="-L$rvnglib -lrevenge-generators-0.0"
make -j$(nproc)
wpdinc=$(pwd)/inc
wpdlib=$(pwd)/src/lib
popd

pushd libwpg
./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tools --enable-fuzzers \
    WPD_CFLAGS=-I$wpdinc WPD_LIBS="-L$wpdlib -lwpd-0.10" \
    REVENGE_CFLAGS=-I$rvnginc REVENGE_LIBS="-L$rvnglib -lrevenge-0.0" \
    REVENGE_STREAM_CFLAGS=-I$rvnginc REVENGE_STREAM_LIBS="-L$rvnglib -lrevenge-stream-0.0" \
    REVENGE_GENERATORS_CFLAGS=-I$rvnginc REVENGE_GENERATORS_LIBS="-L$rvnglib -lrevenge-generators-0.0"
make -j$(nproc)
popd

pushd libstaroffice
./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tools --enable-fuzzers \
    REVENGE_CFLAGS=-I$rvnginc REVENGE_LIBS="-L$rvnglib -lrevenge-0.0" \
    REVENGE_STREAM_CFLAGS=-I$rvnginc REVENGE_STREAM_LIBS="-L$rvnglib -lrevenge-stream-0.0" \
    REVENGE_GENERATORS_CFLAGS=-I$rvnginc REVENGE_GENERATORS_LIBS="-L$rvnglib -lrevenge-generators-0.0"
make -j$(nproc)
popd

pushd libwps
./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tools --enable-fuzzers \
    REVENGE_CFLAGS=-I$rvnginc REVENGE_LIBS="-L$rvnglib -lrevenge-0.0" \
    REVENGE_STREAM_CFLAGS=-I$rvnginc REVENGE_STREAM_LIBS="-L$rvnglib -lrevenge-stream-0.0" \
    REVENGE_GENERATORS_CFLAGS=-I$rvnginc REVENGE_GENERATORS_LIBS="-L$rvnglib -lrevenge-generators-0.0"
make -j$(nproc)
popd

pushd libmwaw
./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tools --disable-zip --enable-fuzzers \
    REVENGE_CFLAGS=-I$rvnginc REVENGE_LIBS="-L$rvnglib -lrevenge-0.0 -lrevenge-stream-0.0" \
    REVENGE_GENERATORS_CFLAGS=-I$rvnginc REVENGE_GENERATORS_LIBS="-L$rvnglib -lrevenge-generators-0.0"
make -j$(nproc)
popd

pushd libe-book
./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tools --enable-fuzzers \
    LDFLAGS=-L$staticlib \
    XML_LIBS="-lxml2 -llzma" \
    LANGTAG_LIBS="-llangtag -lglib-2.0 -lpcre" \
    REVENGE_CFLAGS=-I$rvnginc REVENGE_LIBS="-L$rvnglib -lrevenge-0.0" \
    REVENGE_STREAM_CFLAGS=-I$rvnginc REVENGE_STREAM_LIBS="-L$rvnglib -lrevenge-stream-0.0" \
    REVENGE_GENERATORS_CFLAGS=-I$rvnginc REVENGE_GENERATORS_LIBS="-L$rvnglib -lrevenge-generators-0.0"
make -j$(nproc)
popd

pushd libabw
./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tools --enable-fuzzers \
    LDFLAGS=-L$staticlib \
    LIBXML_LIBS="-lxml2 -llzma -licuuc -licudata" \
    REVENGE_CFLAGS=-I$rvnginc REVENGE_LIBS="-L$rvnglib -lrevenge-0.0" \
    REVENGE_STREAM_CFLAGS=-I$rvnginc REVENGE_STREAM_LIBS="-L$rvnglib -lrevenge-stream-0.0" \
    REVENGE_GENERATORS_CFLAGS=-I$rvnginc REVENGE_GENERATORS_LIBS="-L$rvnglib -lrevenge-generators-0.0"
make -j$(nproc)
popd

cp */src/fuzz/*fuzzer $OUT
cp *_seed_corpus.zip $OUT
cp *.options $OUT
cp *.dict $OUT

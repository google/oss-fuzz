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
./configure --disable-shared --enable-static CPPFLAGS="$ZLIB_CFLAGS" LDFLAGS="$ZLIB_LIBS"
make -j$(nproc)
export LIBPNG_CFLAGS="-I$(pwd)"
export LIBPNG_LIBS="-L$(pwd) -lpng16"
popd

tar -xzf $SRC/libxml2-2.9.7.tar.gz
pushd libxml2-2.9.7
./configure --disable-shared --enable-static --disable-ipv6 --without-python --without-zlib --without-lzma
make -j$(nproc)
export LIBXML_CFLAGS="-I$(pwd)/include"
export LIBXML_LIBS="-L$(pwd) -lxml2"
export XML_CFLAGS="$LIBXML_CFLAGS"
export XML_LIBS="$LIBXML_LIBS"
popd

tar -xzf $SRC/icu4c-60_2-src.tgz
pushd icu/source
patch -p2 < $SRC/icu4c-ubsan.patch
patch -p3 < $SRC/ofz3670.patch
patch -p3 < $SRC/ofz4860.patch
./configure --disable-shared --enable-static --with-data-packaging=static --disable-dyload --disable-strict \
    --disable-layout --disable-samples --disable-extras --disable-icuio --disable-plugins \
    CPPFLAGS=-DU_USE_STRTOD_L=0
make -j$(nproc)
export ICU_CFLAGS="-I$(pwd) -I$(pwd)/i18n -I$(pwd)/common"
export ICU_LIBS="-L$(pwd)/lib -licui18n -licuuc -licudata"
popd

tar -xjf $SRC/boost_1_66_0.tar.bz2
pushd boost_1_66_0
patch -p2 < $SRC/ofz2894.patch
patch -p2 < $SRC/ofz4303.patch
export CPPFLAGS="-I$(pwd)"
popd

tar -xjf $SRC/mdds-1.3.1.tar.bz2
pushd mdds-1.3.1
./configure
export MDDS_CFLAGS="-I$(pwd)/include"
export MDDS_LIBS=' '
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
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers
make -j$(nproc)
popd

pushd libcdr
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers --disable-tests
make -j$(nproc)
popd

pushd libvisio
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers --disable-tests
make -j$(nproc)
popd

pushd libzmf
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers --disable-tests
make -j$(nproc)
popd

pushd libpagemaker
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers
make -j$(nproc)
popd

pushd libfreehand
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers --disable-tests
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
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --disable-zip --enable-fuzzers
make -C src/lib -j$(nproc)
# Link with less parallelism to avoid memory problems on the builders
make -j2
popd

pushd libe-book
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static \
    --without-tools --enable-fuzzers --without-liblangtag --disable-tests
make -j$(nproc)
popd

pushd libabw
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers
make -j$(nproc)
popd

pushd libetonyek
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static \
    --without-tools --enable-fuzzers --with-mdds=0.x --without-liblangtag --disable-tests
make -j$(nproc)
popd

pushd libqxp
./autogen.sh
./configure --without-docs --disable-werror --disable-shared --enable-static --disable-tools --enable-fuzzers --disable-tests
make -j$(nproc)
popd

cp */src/fuzz/*fuzzer $OUT
cp */src/fuzz/*.dict $OUT
cp *_seed_corpus.zip $OUT
cp *.options $OUT

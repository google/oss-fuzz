#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

export WGET2_DEPS_PATH=$SRC/wget2_deps
export PKG_CONFIG_PATH=$WGET2_DEPS_PATH/lib64/pkgconfig:$WGET2_DEPS_PATH/lib/pkgconfig
export CPPFLAGS="-I$WGET2_DEPS_PATH/include"
export LDFLAGS="-L$WGET2_DEPS_PATH/lib"
export GNULIB_SRCDIR=$SRC/gnulib
export LLVM_PROFILE_FILE=/tmp/prof.test

cd $SRC/libunistring
./configure --enable-static --disable-shared --prefix=$WGET2_DEPS_PATH
make -j$(nproc)
make install

cd $SRC/libidn2
./configure --enable-static --disable-shared --disable-doc --disable-gcc-warnings --prefix=$WGET2_DEPS_PATH
make -j$(nproc)
make install

cd $SRC/libpsl
./autogen.sh
./configure --enable-static --disable-shared --disable-gtk-doc --enable-runtime=libidn2 --enable-builtin=libidn2 --prefix=$WGET2_DEPS_PATH
make -j$(nproc)
make install

GNUTLS_CONFIGURE_FLAGS=""
NETTLE_CONFIGURE_FLAGS=""
if [[ $CFLAGS = *sanitize=memory* ]]; then
  GNUTLS_CONFIGURE_FLAGS="--disable-hardware-acceleration"
  NETTLE_CONFIGURE_FLAGS="--disable-assembler --disable-fat"
fi

# We could use GMP from git repository to avoid false positives in
# sanitizers, but GMP doesn't compile with clang. We use gmp-mini
# instead.
cd $SRC/nettle
bash .bootstrap
./configure --enable-mini-gmp --enable-static --disable-shared --disable-documentation --prefix=$WGET2_DEPS_PATH $NETTLE_CONFIGURE_FLAGS
( make -j$(nproc) || make -j$(nproc) ) && make install
if test $? != 0;then
        echo "Failed to compile nettle"
        exit 1
fi

cd $SRC/gnutls
touch .submodule.stamp
./bootstrap
GNUTLS_CFLAGS=`echo $CFLAGS|sed s/-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION//`
LIBS="-lunistring" \
CFLAGS="$GNUTLS_CFLAGS" \
./configure --with-nettle-mini --enable-gcc-warnings --enable-static --disable-shared --with-included-libtasn1 \
    --with-included-unistring --without-p11-kit --disable-doc --disable-tests --disable-tools --disable-cxx \
    --disable-maintainer-mode --disable-libdane --disable-gcc-warnings --disable-full-test-suite \
    --prefix=$WGET2_DEPS_PATH $GNUTLS_CONFIGURE_FLAGS
make -j$(nproc)
make install

# avoid iconv() memleak on Ubuntu 16.04 image (breaks test suite)
export ASAN_OPTIONS=detect_leaks=0

cd $SRC/wget2
./bootstrap

LIBS="-lgnutls -lhogweed -lnettle -lidn2 -lunistring -lpsl -lz" \
  ./configure -C --enable-static --disable-shared --disable-doc --without-plugin-support
make clean
make -j$(nproc)
make -j$(nproc) -C unit-tests check
make -j$(nproc) -C fuzz check

LIBS="-lgnutls -lhogweed -lnettle -lidn2 -lunistring -lpsl -lz" \
  ./configure -C --enable-fuzzing --enable-static --disable-shared --disable-doc --without-plugin-support
make clean
make -j$(nproc) -C lib
make -j$(nproc) -C include
make -j$(nproc) -C libwget
make -j$(nproc) -C src

# Ensure our libraries can be found
ln -s $WGET2_DEPS_PATH/lib64/libhogweed.a $WGET2_DEPS_PATH/lib/libhogweed.a
ln -s $WGET2_DEPS_PATH/lib64/libnettle.a  $WGET2_DEPS_PATH/lib/libnettle.a

# build fuzzers
cd fuzz

CXXFLAGS="$CXXFLAGS -L$WGET2_DEPS_PATH/lib/" make oss-fuzz

find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.options' -exec cp -v '{}' $OUT ';'

for dir in *_fuzzer.in; do
  fuzzer=$(basename $dir .in)
  zip -rj "$OUT/${fuzzer}_seed_corpus.zip" "${dir}/"
done

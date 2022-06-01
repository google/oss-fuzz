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

export WGET_DEPS_PATH=$SRC/wget_deps
export PKG_CONFIG_PATH=$WGET_DEPS_PATH/lib64/pkgconfig:$WGET_DEPS_PATH/lib/pkgconfig
export CPPFLAGS="-I$WGET_DEPS_PATH/include"
export CFLAGS="$CFLAGS -I$WGET_DEPS_PATH/include -L$WGET_DEPS_PATH/lib"
export LDFLAGS="-L$WGET_DEPS_PATH/lib"
export GNULIB_SRCDIR=$SRC/gnulib
export LLVM_PROFILE_FILE=/tmp/prof.test

cd $SRC/libunistring
./autogen.sh
./configure --enable-static --disable-shared --prefix=$WGET_DEPS_PATH --cache-file ../config.cache
make -j$(nproc)
make install

cd $SRC/libidn2
./bootstrap
./configure --enable-static --disable-shared --disable-doc --disable-gcc-warnings --prefix=$WGET_DEPS_PATH --cache-file ../config.cache
make -j$(nproc)
make install

cd $SRC/libpsl
./autogen.sh
./configure --enable-static --disable-shared --disable-gtk-doc --enable-runtime=libidn2 --enable-builtin=libidn2 --prefix=$WGET_DEPS_PATH --cache-file ../config.cache
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
./configure --enable-mini-gmp --enable-static --disable-shared --disable-documentation --prefix=$WGET_DEPS_PATH $NETTLE_CONFIGURE_FLAGS --cache-file ../config.cache
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
    --prefix=$WGET_DEPS_PATH $GNUTLS_CONFIGURE_FLAGS
make -j$(nproc)
make install


# avoid iconv() memleak on Ubuntu 16.04 image (breaks test suite)
export ASAN_OPTIONS=detect_leaks=0

# Ensure our libraries can be found
ln -s $WGET_DEPS_PATH/lib64/libhogweed.a $WGET_DEPS_PATH/lib/libhogweed.a
ln -s $WGET_DEPS_PATH/lib64/libnettle.a  $WGET_DEPS_PATH/lib/libnettle.a

cd $SRC/wget
./bootstrap --skip-po
autoreconf -fi

# build and run non-networking tests
LIBS="-lgnutls -lhogweed -lnettle -lidn2 -lunistring -lpsl" \
./configure -C
make clean
make -j$(nproc)
make -j$(nproc) -C fuzz check

# build for fuzzing
LIBS="-lgnutls -lhogweed -lnettle -lidn2 -lunistring -lpsl" \
./configure --enable-fuzzing -C
make clean
make -j$(nproc) -C lib
make -j$(nproc) -C src

# build fuzzers
cd fuzz
make -j$(nproc) ../src/libunittest.a
make oss-fuzz

find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.options' -exec cp -v '{}' $OUT ';'

for dir in *_fuzzer.in; do
  fuzzer=$(basename $dir .in)
  zip -rj "$OUT/${fuzzer}_seed_corpus.zip" "${dir}/"
done

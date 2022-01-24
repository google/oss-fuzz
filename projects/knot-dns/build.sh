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


# Compile and install dependencies for static linking
# Cribbed from projects/wget2, thanks rockdaboot@gmail.com

export DEPS_PATH=$SRC/knot_deps
export PKG_CONFIG_PATH=$DEPS_PATH/lib64/pkgconfig:$DEPS_PATH/lib/pkgconfig
export CPPFLAGS="-I$DEPS_PATH/include"
export LDFLAGS="-L$DEPS_PATH/lib"
export GNULIB_SRCDIR=$SRC/gnulib
export GNULIB_TOOL=$SRC/gnulib/gnulib-tool

cd $SRC/libunistring
./autogen.sh
./configure --enable-static --disable-shared --prefix=$DEPS_PATH
make -j$(nproc)
make install

GNUTLS_CONFIGURE_FLAGS=""
NETTLE_CONFIGURE_FLAGS=""
if [[ $CFLAGS = *sanitize=memory* ]]; then
  GNUTLS_CONFIGURE_FLAGS="--disable-hardware-acceleration"
  NETTLE_CONFIGURE_FLAGS="--disable-assembler --disable-fat"
fi

cd $SRC/nettle
bash .bootstrap
./configure --enable-mini-gmp --enable-static --disable-shared --disable-documentation --prefix=$DEPS_PATH $NETTLE_CONFIGURE_FLAGS
( make -j$(nproc) || make -j$(nproc) ) && make install

cd $SRC/gnutls
touch .submodule.stamp
./bootstrap
GNUTLS_CFLAGS=`echo $CFLAGS|sed s/-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION//`
LIBS="-lunistring" \
CFLAGS="$GNUTLS_CFLAGS" \
./configure --with-nettle-mini --enable-gcc-warnings --enable-static --disable-shared --with-included-libtasn1 \
    --with-included-unistring --without-p11-kit --disable-doc --disable-tests --disable-tools --disable-cxx \
    --disable-maintainer-mode --disable-libdane --disable-gcc-warnings --prefix=$DEPS_PATH $GNUTLS_CONFIGURE_FLAGS
make -j$(nproc)
make install

cd $SRC/lmdb/libraries/liblmdb
make -j$(nproc)
make install

# Compile knot, install fuzzers to $OUT

cd $SRC/knot-dns
sed -i 's/-llmdb/-Wl,-Bstatic,-llmdb,-Bdynamic/' configure.ac
autoreconf -if
./configure --with-oss-fuzz=yes --disable-shared --enable-static --disable-daemon --disable-utilities --disable-documentation \
    --disable-fastparser --disable-modules
make -j$(nproc)
cd $SRC/knot-dns/tests-fuzz
make check
/bin/bash ../libtool   --mode=install /usr/bin/install -c fuzz_packet fuzz_zscanner fuzz_dname_to_str fuzz_dname_from_str "$OUT"

# Set up fuzzing seeds

git submodule update --init -- ./fuzz_packet.in
git submodule update --init -- ./fuzz_zscanner.in
# ./fuzz_dname_to_str.in/ and ./fuzz_dname_from_str.in/ are stored in the base repository
find ./fuzz_packet.in/         -type f -exec zip -u $OUT/fuzz_packet_seed_corpus.zip {} \;
find ./fuzz_zscanner.in/       -type f -exec zip -u $OUT/fuzz_zscanner_seed_corpus.zip {} \;
find ./fuzz_dname_to_str.in/   -type f -exec zip -u $OUT/fuzz_dname_to_str_seed_corpus.zip {} \;
find ./fuzz_dname_from_str.in/ -type f -exec zip -u $OUT/fuzz_dname_from_str_seed_corpus.zip {} \;

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

export DEPS_PATH=$SRC/deps
export PKG_CONFIG_PATH=$DEPS_PATH/lib64/pkgconfig:$DEPS_PATH/lib/pkgconfig
export CPPFLAGS="-I$DEPS_PATH/include"
export LDFLAGS="-L$DEPS_PATH/lib -L$DEPS_PATH/lib64"
export GNULIB_SRCDIR=$SRC/gnulib

cd $SRC/libunistring
./autogen.sh
ASAN_OPTIONS=detect_leaks=0 \
  ./configure --enable-static --disable-shared --prefix=$DEPS_PATH
make -j$(nproc)
make install

cd $SRC/libidn2
./bootstrap
ASAN_OPTIONS=detect_leaks=0 \
  ./configure --enable-static --disable-shared --disable-doc --disable-gcc-warnings --prefix=$DEPS_PATH
make -j$(nproc)
make install

# always disable assembly in GMP to avoid issues due to SIGILL
#   https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=3119
#   https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=3159
GMP_CONFIGURE_FLAGS="--disable-assembly --disable-fat"

cd $SRC/gmp
bash .bootstrap
ASAN_OPTIONS=detect_leaks=0 \
  ./configure --disable-shared --prefix=$DEPS_PATH $GMP_CONFIGURE_FLAGS
make -j$(nproc)
make install

cd $SRC/libtasn1
bash bootstrap
./configure --disable-gcc-warnings --disable-gtk-doc --disable-gtk-doc-pdf --disable-doc \
  --disable-shared --enable-static --prefix=$DEPS_PATH
make -j$(nproc)
make install

NETTLE_CONFIGURE_FLAGS=""
if [[ $CFLAGS = *sanitize=memory* ]]; then
  NETTLE_CONFIGURE_FLAGS="--disable-assembler --disable-fat"
fi
cd $SRC/nettle
bash .bootstrap
ASAN_OPTIONS=detect_leaks=0 \
  ./configure --enable-static --disable-shared --disable-documentation --prefix=$DEPS_PATH $NETTLE_CONFIGURE_FLAGS
( make -j$(nproc) || make -j$(nproc) ) && make install
if test $? != 0; then
  echo "Failed to compile nettle"
  exit 1
fi


GNUTLS_CONFIGURE_FLAGS=""
if [[ $CFLAGS = *sanitize=memory* ]]; then
  GNUTLS_CONFIGURE_FLAGS="--disable-hardware-acceleration"
fi
cd $SRC/gnutls
./bootstrap
ASAN_OPTIONS=detect_leaks=0 LIBS="-lunistring" CXXFLAGS="$CXXFLAGS -L$DEPS_PATH/lib" \
  ./configure --enable-fuzzer-target --disable-gcc-warnings --enable-static --disable-shared --disable-doc --disable-tests \
    --disable-tools --disable-cxx --disable-maintainer-mode --disable-libdane --without-p11-kit \
    --disable-full-test-suite $GNUTLS_CONFIGURE_FLAGS

# Do not use the syscall interface for randomness in oss-fuzz, it seems
# to confuse memory sanitizer.
sed -i 's|include <sys/syscall.h>|include <sys/syscall.h>\n#undef SYS_getrandom|' lib/nettle/sysrng-linux.c

make -j$(nproc) -C gl
make -j$(nproc) -C lib

cd fuzz
make oss-fuzz
find . -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.options' -exec cp -v '{}' $OUT ';'

for dir in *_fuzzer.in; do
    fuzzer=$(basename $dir .in)
    zip -rj "$OUT/${fuzzer}_seed_corpus.zip" "${dir}/"
done

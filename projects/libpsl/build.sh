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
export PKG_CONFIG_PATH=$DEPS_PATH/lib/pkgconfig
export CPPFLAGS="-I$DEPS_PATH/include"
export LDFLAGS="-L$DEPS_PATH/lib"

cd $SRC/icu/source
./configure --disable-shared --enable-static --disable-extras --disable-icuio --disable-layoutex \
  --disable-tests --disable-samples --with-data-packaging=static --prefix=$DEPS_PATH
# ugly hack to avoid build error
echo '#include <locale.h>' >>i18n/digitlst.h
make -j$(nproc)
make install

cd $SRC/libunistring
./autogen.sh
./configure --enable-static --disable-shared --prefix=$DEPS_PATH
make -j$(nproc)
make install

cd $SRC/libidn
make CFGFLAGS="--enable-static --disable-shared --disable-doc --prefix=$DEPS_PATH"
make clean
make -j1
make -j$(nproc) check
make install

cd $SRC/libidn2
./bootstrap
./configure --enable-static --disable-shared --disable-doc --disable-gcc-warnings --prefix=$DEPS_PATH
make -j$(nproc)
make install


# avoid iconv() memleak on Ubuntu 16.04 image (breaks test suite)
export ASAN_OPTIONS=detect_leaks=0

cd $SRC/libpsl
./autogen.sh
export CXXFLAGS="$CXXFLAGS -L$DEPS_PATH/lib/"
for build in libicu libidn2 libidn none; do
  if test $build = "none"; then
    BUILD_FLAGS="--disable-runtime --disable-builtin"
  else
    BUILD_FLAGS="--enable-runtime=$build --enable-builtin=$build"
  fi
  LIBS="-lstdc++" ./configure --enable-static --disable-shared --disable-gtk-doc $BUILD_FLAGS --prefix=$DEPS_PATH
  make clean
  make -j$(nproc)
  make -j$(nproc) check
  make -C fuzz oss-fuzz
done

cd fuzz
find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.options' -exec cp -v '{}' $OUT ';'

for fuzzer in *_fuzzer; do
    cp -p "${fuzzer}" "$OUT"

    if [ -d "${fuzzer}.in/" ]; then
        zip -rj "$OUT/${fuzzer}_seed_corpus.zip" "${fuzzer}.in/"
    fi
done

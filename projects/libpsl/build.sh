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
export CONFIG_SITE=$SRC/config.site
export GNULIB_SRCDIR=$SRC/gnulib
export GNULIB_TOOL=$GNULIB_SRCDIR/gnulib-tool


cd $SRC/icu/source
UBSAN_OPTIONS=detect_leaks=0 \
CFLAGS="$CFLAGS -fno-sanitize=vptr" \
CXXFLAGS="$CXXFLAGS -fno-sanitize=vptr" \
CPPFLAGS="$CPPFLAGS -fno-sanitize=vptr" \
./configure --disable-shared --enable-static --disable-extras --disable-icuio --disable-layoutex \
  --disable-tests --disable-samples --with-data-packaging=static --prefix=$DEPS_PATH
# ugly hack to avoid build error
echo '#include <locale.h>' >>i18n/digitlst.h

# Hack so that upgrade to Ubuntu 20.04 works.
ln -s /usr/include/locale.h /usr/include/xlocale.h

make -j
make install

cd $SRC/libunistring
./autogen.sh
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=detect_leaks=0 \
  ./configure --enable-static --disable-shared --prefix=$DEPS_PATH
make -j
make install

cd $SRC/libidn
./bootstrap
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=detect_leaks=0 \
  ./configure --enable-static --disable-shared --disable-doc --prefix=$DEPS_PATH
make -j
make install

cd $SRC/libidn2
./bootstrap
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=detect_leaks=0 \
  ./configure --enable-static --disable-shared --disable-doc --disable-gcc-warnings --prefix=$DEPS_PATH
make -j
make install


cd $SRC/libpsl
./autogen.sh
export CXXFLAGS="$CXXFLAGS -L$DEPS_PATH/lib/"
if test $SANITIZER = "undefined"; then
  # libicu doesn't work with -fsanitizer=undefined, see projects/icu/project.yaml
  builds="libidn2 libidn none"
else
  builds="libicu libidn2 libidn none"
fi
for build in $builds; do
  unset LIBS
  if test $build = "none"; then
    BUILD_FLAGS="--disable-runtime --disable-builtin"
    # convert PSL to NFC
    cp -p list/public_suffix_list.dat list/public_suffix_list.dat.org
    LC_ALL=C.UTF-8 python3 -c $'import unicodedata\nimport sys\nfor line in sys.stdin:\n  sys.stdout.write(unicodedata.normalize("NFC", line))' <list/public_suffix_list.dat.org >list/public_suffix_list.dat
  else
    BUILD_FLAGS="--enable-runtime=$build --enable-builtin=$build"
    if test $build = "libicu"; then
      export LIBS="-lstdc++"
    fi
  fi
  # older m4 iconv detection has memleaks, so switch leak detection off
  ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=detect_leaks=0 \
    ./configure --enable-fuzzing --enable-static --disable-shared --disable-gtk-doc $BUILD_FLAGS --prefix=$DEPS_PATH
  make clean
  make -j
  make -j check
  make -C fuzz oss-fuzz
  find fuzz -name '*_fuzzer' -exec cp -v '{}' $OUT ';'
done

cd fuzz
find . -name '*_fuzzer.dict' -exec cp -v '{}' $OUT ';'
find . -name '*_fuzzer.options' -exec cp -v '{}' $OUT ';'

for dir in *_fuzzer.in; do
    fuzzer=$(basename $dir .in)
    zip -rj "$OUT/${fuzzer}_seed_corpus.zip" "${dir}/"
done

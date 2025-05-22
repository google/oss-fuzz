#!/bin/bash -eu
# Copyright 2022 Google LLC
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

# Build glib with sanitizer support
cd glib
mkdir build
cd build
meson --prefix=/usr --buildtype=release -Db_lundef=false -Ddefault_library=static -Dlibmount=disabled
ninja
ninja install

# Build libostree
cd $SRC/ostree
env NOCONFIGURE=1 ./autogen.sh
./configure --enable-static --without-selinux
make V=1

# This needs to be able to fail in case some tests are breaking.
make check V=1 || true

# Build fuzzers
cp $SRC/fuzz*.c ./tests/

FUZZ_LIBS="./.libs/libbsdiff.a \
           ./.libs/libglnx.a \
           ./.libs/libotutil.a \
           -L/usr/lib/x86_64-linux-gnu \
           ./.libs/libostree-1.a \
           ./.libs/libostreetest.a \
           ./.libs/libostree-1.a \
           -l:libgpgme.a \
           -l:libassuan.a \
           /usr/lib/x86_64-linux-gnu/libgpg-error.so \
           -l:liblzma.a \
           -l:libgio-2.0.a \
           -lresolv \
           -l:libgobject-2.0.a \
           -l:libffi.a \
           -l:libgmodule-2.0.a \
           -l:libglib-2.0.a \
           -lm \
           -l:libz.a \
           -l:libselinux.a \
           -pthread \
           -l:libpcre2-8.a"

FUZZ_INCLUDES="-I./src/libotutil \
               -I./src/libostree \
               -I./src/libostree \
               -I./src/ostree \
               -I./libglnx \
               -I/usr/include/gio-unix-2.0 \
               -I/usr/include/glib-2.0 \
               -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
               -DPKGLIBEXECDIR=\"/usr/local/libexec/libostree\""

FUZZ_DEFINES="-DHAVE_CONFIG_H \
              -I. \
              -DDATADIR=\"/usr/local/share\" \
              -DLIBEXECDIR=\"/usr/local/libexec\" \
              -DLOCALEDIR=\"/usr/local/share/locale\" \
              -DSYSCONFDIR=\"/usr/local/etc\" \
              -DTARGET_PREFIX=\"/usr/local\" \
              -DOSTREE_COMPILATION \
              -DG_LOG_DOMAIN=\"OSTree\" \
              -DOSTREE_GITREV=\"v2022.2-41-gf21944da1cf24cc2bbf1d4dfbd3aaa698d4f0a70\" \
              -DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_66 \
              -DSOUP_VERSION_MIN_REQUIRED=SOUP_VERSION_2_40"

FUZZ_WERROR=""

for fuzz in repo bsdiff; do
  $CC $CFLAGS $FUZZ_DEFINES $FUZZ_INCLUDES -o tests/fuzz-$fuzz.o -c tests/fuzz-$fuzz.c
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE $FUZZ_INCLUDES -o $OUT/fuzz-$fuzz  tests/fuzz-$fuzz.o $FUZZ_LIBS
done

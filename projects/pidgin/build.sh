#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# Place to keep dependencies for static linking
DEPS=/deps
mkdir ${DEPS}


# Build libffi
cd $SRC
tar xvfz libffi-3.2.1.tar.gz
cd libffi-3.2.1
./configure --disable-shared
make -j$(nproc)
export LIBFFI_LIBS="-L/src/libffi-3.2.1 libraries/ -lffi"
cp ./x86_64-unknown-linux-gnu/.libs/libffi.a ${DEPS}/


# Build libxml2
cd $SRC/libxml2
./autogen.sh \
    --disable-shared \
    --without-debug \
    --without-ftp \
    --without-http \
    --without-legacy \
    --without-python
make -j$(nproc)
make install
cp .libs/libxml2.a ${DEPS}/


# Build glib
cd $SRC/glib
GLIB_BUILD=$WORK/meson
rm -rf $GLIB_BUILD
mkdir $GLIB_BUILD
meson $GLIB_BUILD \
  -Db_lundef=false \
  -Ddefault_library=static \
  -Dlibmount=disabled
ninja -C $GLIB_BUILD
ninja -C $GLIB_BUILD install

cp ${GLIB_BUILD}/gobject/libgobject-2.0.a ${DEPS}/
cp ${GLIB_BUILD}/gmodule/libgmodule-2.0.a ${DEPS}/
cp ${GLIB_BUILD}/glib/libglib-2.0.a ${DEPS}/


# Build Pidgin
cd $SRC 
tar -xf pidgin-2.14.10.tar.bz2
mv pidgin-2.14.10 pidgin
cd pidgin
./configure --disable-consoleui \
            --disable-shared \
            --disable-screensaver \
            --disable-sm \
            --disable-gtkspell \
            --disable-gevolution \
            --enable-gnutls=no \
            --disable-gstreamer \
            --disable-vv \
            --disable-idn \
            --disable-meanwhile \
            --disable-avahi \
            --disable-dbus \
            --disable-perl \
            --disable-tcl \
            --disable-cyrus-sasl \
            --disable-gtkui \
            --enable-nss=no
make -j$(nproc)


# Build fuzzers
readonly FUZZERS=( \
  pidgin_xml_fuzzer
  pidgin_utils_fuzzer
)

cd libpurple
cp $SRC/*fuzzer.c .

for fuzzer in "${FUZZERS[@]}"; do
  $CC $CFLAGS -DHAVE_CONFIG_H \
    -I. \
    -I.. \
    -I${SRC}/glib \
    -I${SRC}/glib/glib \
    -I${SRC}/glib/gmodule \
    -I${GLIB_BUILD} \
    -I${GLIB_BUILD}/glib \
    -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
    -I/usr/local/include/libxml2  \
    -I/src/pidgin/libpurple/protocols/jabber \
    -c $fuzzer.c \
    -o $fuzzer.o

  $CC $CXXFLAGS $LIB_FUZZING_ENGINE $fuzzer.o \
    -o $OUT/$fuzzer \
    /src/pidgin/libpurple/protocols/jabber/.libs/libjabber.a \
    ./.libs/libpurple.a \
    ${DEPS}/libgobject-2.0.a \
    ${DEPS}/libgmodule-2.0.a \
    ${DEPS}/libglib-2.0.a \
    ${DEPS}/libxml2.a \
    ${DEPS}/libffi.a \
    -lresolv -lz -llzma -l:libpcre2-8.a
done

zip $OUT/pidgin_xml_fuzzer_seed_corpus.zip $SRC/go-fuzz-corpus/xml/corpus/*
cp $SRC/fuzzing/dictionaries/xml.dict $OUT/pidgin_xml_fuzzer.dict

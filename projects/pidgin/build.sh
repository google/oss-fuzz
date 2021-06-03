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


# Build libffi
cd $SRC
tar xvfz libffi-3.2.1.tar.gz
cd libffi-3.2.1
./configure --disable-shared
make -j$(nproc)
export LIBFFI_LIBS="-L/src/libffi-3.2.1 libraries/ -lffi"


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


# Build glib
cd $SRC/glib
BUILD=$WORK/meson
rm -rf $BUILD
mkdir $BUILD
meson $BUILD \
  -Db_lundef=false \
  -Ddefault_library=static \
  -Dlibmount=disabled
ninja -C $BUILD
ninja -C $BUILD install


# Build Pidgin
cd $SRC 
tar -xf pidgin-2.14.4.tar.bz2
cd pidgin-2.14.4
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
cd libpurple
cp $SRC/pidgin_xml_fuzzer.c .
$CC $CFLAGS -DHAVE_CONFIG_H \
  -I. \
  -I.. \
  -I/src/pidgin-2.14.4/libpurple/protocols/jabber \
  -I/src/glib/glib \
  -I/src/glib \
  -I/work/meson/glib \
  -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
  -I/usr/local/include/libxml2 \
  -c pidgin_xml_fuzzer.c \
  -o pidgin_xml_fuzzer.o

$CC $CXXFLAGS $LIB_FUZZING_ENGINE pidgin_xml_fuzzer.o \
  -o $OUT/pidgin_xml_fuzzer ./.libs/libpurple.a \
  /src/libxml2/.libs/libxml2.a \
  /work/meson/gobject/libgobject-2.0.a \
  /work/meson/gmodule/libgmodule-2.0.a \
  /work/meson/glib/libglib-2.0.a \
  /src/libffi-3.2.1/x86_64-unknown-linux-gnu/.libs/libffi.a \
  -lresolv -lz -llzma
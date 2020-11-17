#!/bin/bash -eu
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-1.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
PREFIX=$WORK/prefix
mkdir -p $PREFIX

export PKG_CONFIG="`which pkg-config` --static"
export PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig
export PATH=$PREFIX/bin:$PATH

BUILD=$WORK/build

rm -rf $WORK/*
rm -rf $BUILD
mkdir -p $BUILD

cd $WORK

tar xvJf $SRC/glib-2.64.2.tar.xz
cd glib-2.64.2
meson \
    --prefix=$PREFIX \
    --libdir=lib \
    --default-library=static \
    -Db_lundef=false \
    -Doss_fuzz=enabled \
    -Dlibmount=disabled \
    -Dinternal_pcre=true \
    _builddir
ninja -C _builddir
ninja -C _builddir install
cd ..

#ninja -C $BUILD/gdk-pixbuf gdk-pixbuf/libgdk_pixbuf-2.0.a
#pushd $SRC/gdk-pixbuf
#meson \
    #--prefix=$PREFIX \
    #--libdir=lib \
    #--default-library=static \
    #_builddir
#ninja -C _builddir
#ninja -C _builddir install
#popd
pushd $SRC/gdk-pixbuf
meson --prefix=$PREFIX --libdir=lib -Ddefault_library=static -Dintrospection=disabled $BUILD/gdk-pixbuf
ninja -C $BUILD/gdk-pixbuf gdk-pixbuf/libgdk_pixbuf-2.0.a
#ninja -C $BUILD/gdk-pixbuf install

#ninja -C $BUILD/libmediaart libmediaart/libmediaart-2.0.a
#pushd $SRC/libmediaart
#meson \
    #--prefix=$PREFIX \
    #--libdir=lib \
    #--default-library=static \
    #-Ddisable_tests=true \
    #_builddir
#ninja -C _builddir
#ninja -C _builddir install
#popd
pushd $SRC/libmediaart
meson $BUILD/libmediaart -Ddefault_library=static -Ddisable_tests=true -Dintrospection=disabled
ninja -C $BUILD/libmediaart libmediaart/libmediaart-2.0.a

PREDPS_LDFLAGS="-Wl,-Bdynamic -ldl -lrt"
#DEPS="glib-2.0 gio-2.0 gobject-2.0 gdk-pixbuf-2.0 libmediaart-2.0 libffi libpcre expat"
DEPS="glib-2.0 gio-2.0 gobject-2.0 libffi libpcre expat"
BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags $DEPS`"
BUILD_LDFLAGS="-Wl,-static `pkg-config --static --libs $DEPS`"

fuzzers=$(find $SRC/libmediaart/fuzzing/ -name "*_fuzzer.c")
for f in $fuzzers; do
  fuzzer_name=$(basename $f .c)
  $CC $CFLAGS $BUILD_CFLAGS -c -std=c99 -I. \
    $f -o $WORK/${fuzzer_name}.o
  $CXX $CXXFLAGS \
    $WORK/${fuzzer_name}.o -o $OUT/${fuzzer_name} \
    $BUILD/libmediaart/libmediaart/libmediaart-2.0.a \
    $BUILD/gdk-pixbuf/gdk-pixbuf/libgdk_pixbuf-2.0.a \
    $BUILD_LDFLAGS \
    $LIB_FUZZING_ENGINE \
    -Wl,-Bdynamic
done
    #$PREDPS_LDFLAGS \

    #-I. -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
    #$BUILD/libmediaart/libmediaart/libmediaart-2.0.a \
    #$BUILD/gdk-pixbuf/gdk-pixbuf/libgdk_pixbuf-2.0.a \
    #-Wl,-Bstatic -lz -lgmodule-2.0 -lgio-2.0 -lgobject-2.0 -lffi -lglib-2.0 -lpcre -lexpat -lselinux \
    #-Wl,-Bdynamic -ldl -lrt -lpthread
#mv $BUILD/fuzzing/*_fuzzer $OUT/

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

echo "CFLAGS" $CFLAGS
echo "CXXFLAGS" $CXXFLAGS
PREFIX=$WORK/prefix
PLUGIN_DIR=$PREFIX/lib/gstreamer-1.0
export PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig
mkdir -p $PREFIX
export PATH=$PREFIX/bin:$PATH
cd $WORK

# Minimize gst-debug level/code
export CFLAGS="$CFLAGS -DGST_LEVEL_MAX=2"

tar xvJf $SRC/glib-2.54.2.tar.xz
cd glib-2.54.2
./configure --prefix=$PREFIX --enable-static --disable-shared --disable-libmount --with-pcre=internal && make -j$(nproc) && make install
cd ..


for i in gstreamer gst-plugins-base;
do
    mkdir -p $i
    cd $i
    $SRC/$i/autogen.sh --prefix=$PREFIX --disable-shared --enable-static --disable-examples \
		       --disable-gtk-doc --disable-introspection --enable-static-plugins \
		       --disable-gst-tracer-hooks --disable-registry
    make -j$(nproc)
    make install
    cd ..
done

#finally build the binary \o/
BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags glib-2.0 gstreamer-1.0 gstreamer-pbutils-1.0 gstreamer-video-1.0 gstreamer-audio-1.0 gstreamer-app-1.0`"

# List of dependencies libraries we grab from pkg-config
# Should also include dependencies of dependencies (ex: libvorbis depends on libogg)

PKG_DEPS="glib-2.0 gstreamer-1.0 gstreamer-pbutils-1.0 gstreamer-video-1.0 gstreamer-audio-1.0 \
  gstreamer-riff-1.0 gstreamer-tag-1.0 gstreamer-app-1.0 zlib \
  ogg vorbis vorbisenc theoraenc theoradec theora"

# List of all plugins to include
PLUGINS="$PLUGIN_DIR/libgstcoreelements.a \
       $PLUGIN_DIR/libgsttypefindfunctions.a \
       $PLUGIN_DIR/libgstplayback.a \
       $PLUGIN_DIR/libgstapp.a \
       $PLUGIN_DIR/libgstvorbis.a \
       $PLUGIN_DIR/libgsttheora.a \
       $PLUGIN_DIR/libgstogg.a"

# We want to statically link everything, except for shared libraries that are present on
# the base image. Those need to be specified beforehad and explicitely linked dynamically
# If any of the static dependencies require a pre-installed shared library, you need
# to add that library to the following list
PREDEPS_LDFLAGS="-Wl,-Bdynamic -ldl -lm -pthread -lrt -lpthread"

# The libraries we want to statically link to
# This includes dependencies of the gst plugins
BUILD_LDFLAGS="-Wl,-static `pkg-config --static --libs $PKG_DEPS`"

echo
echo "PREDEPS_LDFLAGS" $PREDEPS_LDFLAGS
echo
echo "BUILD_LDFLAGS" $BUILD_LDFLAGS
echo
echo ">>>> BUILDING gst-discoverer.o"
echo

$CC $CFLAGS $BUILD_CFLAGS -c $SRC/gst-ci/fuzzing/gst-discoverer.c -o $SRC/gst-ci/fuzzing/gst-discoverer.o

echo
echo ">>>> LINKING"
echo

$CXX $CXXFLAGS \
      -o $OUT/gst-discoverer \
      $PREDEPS_LDFLAGS \
      $SRC/gst-ci/fuzzing/gst-discoverer.o \
      $PLUGINS \
      $BUILD_LDFLAGS \
      $LIB_FUZZING_ENGINE \
      -Wl,-Bdynamic

echo
echo ">>>> Installing OGG corpus"
echo

cp $SRC/*_seed_corpus.zip $OUT

echo ">>>> BUILDING typefind.o"
echo

$CC $CFLAGS $BUILD_CFLAGS -c $SRC/gst-ci/fuzzing/typefind.c -o $SRC/gst-ci/fuzzing/typefind.o

echo
echo ">>>> LINKING"
echo

$CXX $CXXFLAGS \
      -o $OUT/typefind \
      $PREDEPS_LDFLAGS \
      $SRC/gst-ci/fuzzing/typefind.o \
      $PLUGINS \
      $BUILD_LDFLAGS \
      $LIB_FUZZING_ENGINE \
      -Wl,-Bdynamic

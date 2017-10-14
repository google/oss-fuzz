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

# build project
# e.g.
# ./autogen.sh
# ./configure
# make -j$(nproc) all

# build fuzzers
# e.g.
# $CXX $CXXFLAGS -std=c++11 -Iinclude \
#     /path/to/name_of_fuzzer.cc -o /out/name_of_fuzzer \
#     -lFuzzingEngine /path/to/library.a
BASEFLAGS="-Wno-constant-conversion -Wno-header-guard -Wno-mismatched-tags -O2"
echo "CFLAGS" $CFLAGS
echo "CXXFLAGS" $CXXFLAGS
export CFLAGS="$CFLAGS $BASEFLAGS"
export CXXFLAGS="$CXXFLAGS $BASEFLAGS"
export LDFLAGS="$SANITIZER_FLAGS $COVERAGE_FLAGS"
PREFIX=$WORK/prefix
PLUGIN_DIR=$PREFIX/lib/gstreamer-1.0
export PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig
mkdir -p $PREFIX
cd $WORK

env

# #for i in orc gstreamer gst-plugins-base gst-plugins-good gst-plugins-bad gst-plugins-ugly gst-libav;
for i in orc gstreamer gst-plugins-base;
do
    mkdir -p $i
    cd $i
    $SRC/$i/autogen.sh --prefix=$PREFIX --disable-shared --enable-static --disable-examples --disable-gtk-doc --disable-introspection --enable-static-plugins --disable-gst-tracer-hooks
    make -j$(nproc)
    make install
    cd ..
done

#finally build the binary \o/
BUILD_CFLAGS="$CFLAGS `pkg-config --static --cflags glib-2.0 gstreamer-1.0 gstreamer-pbutils-1.0 gstreamer-video-1.0 gstreamer-audio-1.0 gstreamer-app-1.0 orc-0.4`"

# List of dependencies libraries we grab from pkg-config
# Should also include dependencies of dependencies (ex: libvorbis depends on libogg)

PKG_DEPS="glib-2.0 gstreamer-1.0 gstreamer-pbutils-1.0 gstreamer-video-1.0 gstreamer-audio-1.0 orc-0.4 \
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

# FIXME FIXME FIXME : TRYING WITHOUT GSTAPP
#       $PLUGIN_DIR/libgstapp.a \

# We want to statically link everything, except for shared libraries that are present on
# the base image. Those need to be specified beforehad and explicitely linked dynamically
# If any of the static dependencies require a pre-installed shared library, you need
# to add that library to the following list
PREDEPS_LDFLAGS="-Wl,-Bdynamic -ldl -lm -pthread -lrt -lpthread"

# The libraries we want to statically link to
# This includes dependencies of the gst plugins
#BUILD_LDFLAGS="$LDFLAGS `pkg-config --static --libs $PKG_DEPS` -Wl,-static -lpcre "
BUILD_LDFLAGS="$LDFLAGS -Wl,-static `pkg-config --static --libs $PKG_DEPS`"

for pr in glib-2.0 gstreamer-1.0 gstreamer-pbutils-1.0 gstreamer-video-1.0 gstreamer-audio-1.0 orc-0.4 ogg; do
    echo ">>>>>>>>>>>>>>>>>>>" $pr;
    pkg-config --static --libs $pr;
    pkg-config --debug $pr
done

echo
echo
echo
echo

echo "PREDEPS_LDFLAGS" $PREDEPS_LDFLAGS
echo
echo "BUILD_LDFLAGS" $BUILD_LDFLAGS
echo

echo $CXX $CXXFLAGS $BUILD_CFLAGS \
      -v -Wl,--verbose \
      $SRC//gst-discoverer.c \
      $PLUGINS \
      $LIB_FUZZING_ENGINE \
      -o gst-discoverer \
      $PREDEPS_LDFLAGS \
      $BUILD_LDFLAGS \
      -Wl,-Bdynamic

echo
echo ">>>> BUILDING gst-discoverer.o"
echo

$CC $CFLAGS $BUILD_CFLAGS -c $SRC/gst-discoverer.c -o $SRC/gst-discoverer.o

echo
echo ">>>> LINKING"
echo

$CXX $CXXFLAGS \
      -v -Wl,--verbose \
      -o $OUT/gst-discoverer \
      $PREDEPS_LDFLAGS \
      $SRC/gst-discoverer.o \
      $PLUGINS \
      $BUILD_LDFLAGS \
      $LIB_FUZZING_ENGINE \
      -Wl,-Bdynamic

echo
echo ">>>> Downloading OGG corpus"
echo

cd $OUT
wget -nd https://people.freedesktop.org/~bilboed/gst-discoverer_seed_corpus.zip

cp $LIB_FUZZING_ENGINE /work/



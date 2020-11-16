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

BUILD=$WORK/build

rm -rf $BUILD
mkdir -p $BUILD

pushd $SRC/gdk-pixbuf
meson $BUILD/gdk-pixbuf -Ddefault_library=static
ninja -C $BUILD/gdk-pixbuf gdk-pixbuf/libgdk_pixbuf-2.0.a

pushd $SRC/libmediaart
meson $BUILD/libmediaart -Ddefault_library=static -Ddisable_tests=true
ninja -C $BUILD/libmediaart libmediaart/libmediaart-2.0.a

fuzzers=$(find $SRC/libmediaart/fuzzing/ -name "*_fuzzer.c")
for f in $fuzzers; do
  fuzzer_name=$(basename $f .c)
  $CC $CFLAGS -c -std=c99 \
    -I. -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
    $f -o $WORK/${fuzzer_name}.o
  $CXX $CXXFLAGS $WORK/${fuzzer_name}.o -o $OUT/${fuzzer_name} \
    $BUILD/libmediaart/libmediaart/libmediaart-2.0.a \
    $BUILD/gdk-pixbuf/gdk-pixbuf/libgdk_pixbuf-2.0.a \
    $LIB_FUZZING_ENGINE \
    -Wl,-Bstatic -lgio-2.0 -lgobject-2.0 -lglib-2.0
done

mv $BUILD/fuzzing/*_fuzzer $OUT/

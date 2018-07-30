#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

BUILD=$WORK/meson

rm -rf $BUILD
mkdir $BUILD

meson $BUILD \
  -Ddefault_library=static \
  -Dlibmount=false \
  -Dselinux=false

ninja -C $BUILD

$CC $CFLAGS -I. -Iglib -I$BUILD/glib -c $SRC/fuzz_markup.c
$CXX $CXXFLAGS -lFuzzingEngine \
  fuzz_markup.o -o $OUT/fuzz_markup \
  $BUILD/glib/libglib-2.0.a $BUILD/glib/libcharset/libcharset.a
cp $SRC/fuzz.options $OUT/fuzz_markup.options
find glib/tests -type f -size -32k -name "*.gmarkup" \
  -exec zip -qju $OUT/fuzz_markup_seed_corpus.zip "{}" \;

$CC $CFLAGS -I. -Iglib -I$BUILD/glib -c $SRC/fuzz_bookmark.c
$CXX $CXXFLAGS -lFuzzingEngine \
  fuzz_bookmark.o -o $OUT/fuzz_bookmark \
  $BUILD/glib/libglib-2.0.a $BUILD/glib/libcharset/libcharset.a
cp $SRC/fuzz.options $OUT/fuzz_bookmark.options
find glib/tests -type f -size -32k -name "*.xbel" \
  -exec zip -qju $OUT/fuzz_bookmark_seed_corpus.zip "{}" \;

$CC $CFLAGS -I. -Iglib -I$BUILD/glib -c $SRC/fuzz_key.c
$CXX $CXXFLAGS -lFuzzingEngine \
  fuzz_key.o -o $OUT/fuzz_key \
  $BUILD/glib/libglib-2.0.a $BUILD/glib/libcharset/libcharset.a
cp $SRC/fuzz.options $OUT/fuzz_key.options
find glib/tests -type f -size -32k -name "*.ini" \
  -exec zip -qju $OUT/fuzz_key_seed_corpus.zip "{}" \;

#!/bin/bash -eux
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

cd $SRC/harfbuzz

# setup
build=$WORK/build

# # cleanup
rm -rf $build
mkdir -p $build

# disable sanitize=vptr for harfbuzz since it compiles without rtti
CFLAGS="$CFLAGS -fno-sanitize=vptr" \
CXXFLAGS="$CXXFLAGS -fno-sanitize=vptr" \
meson --default-library=static --wrap-mode=nodownload \
      -Dfuzzer_ldflags="$(echo $LIB_FUZZING_ENGINE)" \
      -Dtests=disabled \
      --prefix=/work/ --libdir=lib $build \
  || (cat build/meson-logs/meson-log.txt && false)
meson install -C $build

cd $SRC/libass

export PKG_CONFIG_PATH=/work/lib/pkgconfig
./autogen.sh
./configure --disable-asm
make -j$(nproc)

$CXX $CXXFLAGS -std=c++11 -I$SRC/libass \
    $SRC/libass_fuzzer.cc -o $OUT/libass_fuzzer \
    $LIB_FUZZING_ENGINE libass/.libs/libass.a \
    -Wl,-Bstatic \
    $(pkg-config --static --libs fontconfig freetype2 fribidi harfbuzz | sed 's/-lm //g') \
    -Wl,-Bdynamic

cp $SRC/*.dict $SRC/*.options $OUT/

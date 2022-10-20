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
./configure FUZZ_CPPFLAGS="-DASS_FUZZMODE=2" --disable-asm --disable-shared --enable-fuzz
make -j "$(nproc)" fuzz/fuzz_ossfuzz
cp fuzz/fuzz_ossfuzz $OUT/libass_fuzzer
cp fuzz/ass.dict $OUT/ass.dict

cp $SRC/*.options $OUT/

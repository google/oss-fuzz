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

# libz
pushd $SRC/zlib
./configure --static --prefix="$WORK"
make -j$(nproc) all
make install
popd

# libzstd
pushd $SRC/zstd
make -j$(nproc) install PREFIX="$WORK"
popd

# libjbig
pushd "$SRC/jbigkit"
make clean
make -j$(nproc) lib
cp "$SRC"/jbigkit/libjbig/*.a "$WORK/lib/"
cp "$SRC"/jbigkit/libjbig/*.h "$WORK/include/"
popd

# libjpeg-turbo
pushd $SRC/libjpeg-turbo
cmake . -DCMAKE_INSTALL_PREFIX="$WORK" -DENABLE_STATIC:bool=on
make -j$(nproc)
make install
popd

# libpng
pushd $SRC/libpng
cat scripts/pnglibconf.dfa | \
  sed -e "s/option WARNING /option WARNING disabled/" \
> scripts/pnglibconf.dfa.temp
mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa
autoreconf -f -i
./configure \
  --prefix="$WORK" \
  --disable-shared \
  --enable-static \
  LDFLAGS="-L$WORK/lib" \
  CPPFLAGS="-I$WORK/include"
make -j$(nproc)
make install
popd

# libwebp
pushd $SRC/libwebp
export WEBP_CFLAGS="$CFLAGS -DWEBP_MAX_IMAGE_SIZE=838860800" # 800MiB
./autogen.sh
./configure \
  --enable-libwebpdemux \
  --enable-libwebpmux \
  --disable-shared \
  --disable-jpeg \
  --disable-tiff \
  --disable-gif \
  --disable-wic \
  --disable-threading \
  --prefix="$WORK" \
  CFLAGS="$WEBP_CFLAGS"
make clean
make -j$(nproc)
make install
popd

# libtiff
pushd "$SRC/libtiff"
cmake . -DCMAKE_INSTALL_PREFIX="$WORK" -DBUILD_SHARED_LIBS=off
make clean
make -j$(nproc)
make install
popd

# leptonica
export LEPTONICA_LIBS="$WORK/lib/libjbig.a $WORK/lib/libzstd.a $WORK/lib/libwebp.a $WORK/lib/libpng.a"
./autogen.sh
./configure \
  --enable-static \
  --disable-shared \
  --with-libpng \
  --with-zlib \
  --with-jpeg \
  --with-libwebp \
  --with-libtiff \
  --prefix="$WORK" \
  LIBS="$LEPTONICA_LIBS" \
  LDFLAGS="-L$WORK/lib" \
  CPPFLAGS="-I$WORK/include"
make -j$(nproc)
make install

$CXX $CXXFLAGS -std=c++11 -I"$WORK/include" \
  "$SRC/pix_rotate_shear_fuzzer.cc" -o "$OUT/pix_rotate_shear_fuzzer" \
  "$WORK/lib/liblept.a" \
  "$WORK/lib/libtiff.a" \
  "$WORK/lib/libwebp.a" \
  "$WORK/lib/libpng.a" \
  "$WORK/lib/libjpeg.a" \
  "$WORK/lib/libjbig.a" \
  "$WORK/lib/libzstd.a" \
  "$WORK/lib/libz.a" \
  $LIB_FUZZING_ENGINE


#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Build CUPS
pushd $SRC/cups
# Fix bad line
sed -i '2110s/\(\s\)f->value/\1(int)f->value/' cups/ppd-cache.c

LSB_BUILD=y ./configure --prefix="$WORK" --libdir="$OUT" --disable-gnutls \
   --disable-libusb --with-components=core

make clean
make install-headers install-libs
make -C filter libs install-libs
install -m755 cups-config "$WORK"/cups-config
popd

rm -rf cups/libs || die
rm -rf freetype || die
rm -rf libpng || die
rm -rf zlib || die

mv $SRC/freetype freetype

CUPSCONFIG="$WORK/cups-config"
CUPS_CFLAGS=$($CUPSCONFIG --cflags)
CUPS_LDFLAGS=$($CUPSCONFIG --ldflags)
CUPS_LIBS=$($CUPSCONFIG --image --libs)
export CXXFLAGS="$CXXFLAGS $CUPS_CFLAGS"

CPPFLAGS="${CPPFLAGS:-} $CUPS_CFLAGS -DPACIFY_VALGRIND" ./autogen.sh \
  CUPSCONFIG=$CUPSCONFIG \
  --enable-freetype --enable-fontconfig \
  --enable-cups --with-ijs --with-jbig2dec \
  --with-drivers=cups,ljet4,laserjet,pxlmono,pxlcolor,pcl3,uniprint
make -j$(nproc) libgs


for fuzzer in gstoraster_pdf_fuzzer gstoraster_fuzzer gstoraster_fuzzer_all_colors; do
  $CXX $CXXFLAGS $CUPS_LDFLAGS -std=c++11 -I. -I$SRC \
    $SRC/${fuzzer}.cc \
    -o "$OUT/${fuzzer}" \
    -Wl,-rpath='$ORIGIN' \
    $CUPS_LIBS \
    $LIB_FUZZING_ENGINE bin/gs.a
done

# Create PDF seed corpus
zip -j "$OUT/gstoraster_pdf_fuzzer_seed_corpus.zip" $SRC/pdf_seeds/*

# Create corpus for gstoraster_fuzzer_all_colors. Only use seeds of a few KB in size.
mkdir -p "$WORK/all_color_seeds"
for f in examples/ridt91.eps examples/snowflak.ps $SRC/pdf_seeds/pdf.pdf; do
  # Prepend a single byte to seed, because it's used to determine the color
  # scheme in the gstoraster_fuzzer_all_colors.
  printf "\x01" | cat - "$f" > tmp_file.txt
  mv tmp_file.txt $f
  s=$(sha1sum "$f" | awk '{print $1}')
  cp "$f" "$WORK/all_color_seeds/$s"
done
zip -j "$OUT/gstoraster_fuzzer_all_colors_seed_corpus.zip" "$WORK"/all_color_seeds/*

# Create seeds for gstoraster_fuzzer
mkdir -p "$WORK/seeds"
for f in examples/*.{ps,pdf}; do
  s=$(sha1sum "$f" | awk '{print $1}')
  cp "$f" "$WORK/seeds/$s"
done

# Create corpus for gstoraster_fuzzer
zip -j "$OUT/gstoraster_fuzzer_seed_corpus.zip" "$WORK"/seeds/*

# Copy out options
cp $SRC/*.options $OUT/

# Copy out dictionary
cp $SRC/dicts/pdf.dict $OUT/gstoraster_pdf_fuzzer.dict

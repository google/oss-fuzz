#!/bin/bash -eu
# Copyright 2017 Google Inc.  #
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

./configure --prefix="$WORK" --disable-shared --disable-docs
make "-j$(nproc)"
make install

$CXX $CXXFLAGS -std=c++11 -I"$WORK/include/ImageMagick-7" "$SRC/imagemagick/fuzz/encoder_list.cc" \
    -o "$WORK/encoder_list" \
    -DMAGICKCORE_HDRI_ENABLE=1 -DMAGICKCORE_QUANTUM_DEPTH=16 \
    "$WORK/lib/libMagick++-7.Q16HDRI.a" \
    "$WORK/lib/libMagickWand-7.Q16HDRI.a" \
    "$WORK/lib/libMagickCore-7.Q16HDRI.a"

for f in $SRC/imagemagick/fuzz/*_fuzzer.cc; do
    fuzzer=$(basename "$f" _fuzzer.cc)
    # encoder_fuzzer is special
    if [ "$fuzzer" = "encoder" ]; then
        continue
    fi
    $CXX $CXXFLAGS -std=c++11 -I"$WORK/include/ImageMagick-7" \
        "$f" -o "$OUT/${fuzzer}_fuzzer" \
        -DMAGICKCORE_HDRI_ENABLE=1 -DMAGICKCORE_QUANTUM_DEPTH=16 \
        -lFuzzingEngine "$WORK/lib/libMagick++-7.Q16HDRI.a" \
        "$WORK/lib/libMagickWand-7.Q16HDRI.a" "$WORK/lib/libMagickCore-7.Q16HDRI.a"
done

for encoder in $("$WORK/encoder_list"); do
    $CXX $CXXFLAGS -std=c++11 -I"$WORK/include/ImageMagick-7" \
        "$SRC/imagemagick/fuzz/encoder_fuzzer.cc" -o "$OUT/encoder_${encoder,,}_fuzzer" \
        -DMAGICKCORE_HDRI_ENABLE=1 -DMAGICKCORE_QUANTUM_DEPTH=16 \
        "-DFUZZ_IMAGEMAGICK_ENCODER=$encoder" \
        -lFuzzingEngine "$WORK/lib/libMagick++-7.Q16HDRI.a" \
        "$WORK/lib/libMagickWand-7.Q16HDRI.a" "$WORK/lib/libMagickCore-7.Q16HDRI.a"
done

mkdir afl_testcases
(cd afl_testcases; tar xvf "$SRC/afl_testcases.tgz")
for format in gif jpg png bmp ico webp tif; do
    mkdir $format
    find afl_testcases -type f -name '*.'$format -exec mv -n {} $format/ \;
    zip -rj $format.zip $format/
    cp $format.zip "$OUT/encoder_${format}_fuzzer_seed_corpus.zip"
done

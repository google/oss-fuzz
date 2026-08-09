#!/bin/bash -eux
# Copyright 2025 Google LLC.
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
##############################################################################

# Prepare wrappers to make recompilation faster.
if [ ! -f /usr/bin/bash.real ]; then
  # Only run this once.
  python /usr/local/bin/make_build_replayable.py
fi


MAGICK_COMPILER=$CXX
MAGICK_COMPILER_FLAGS=$CXXFLAGS
MAGICK_INCLUDE="$WORK/include/ImageMagick-7"
MAGICK_SRC="$SRC/imagemagick/oss-fuzz"
MAGICK_LIBS_NO_FUZZ="$WORK/lib/libMagick++-7.Q16HDRI.a $WORK/lib/libMagickWand-7.Q16HDRI.a $WORK/lib/libMagickCore-7.Q16HDRI.a $WORK/lib/libpng.a $WORK/lib/libtiff.a $WORK/lib/libheif.a $WORK/lib/libde265.a $WORK/lib/libopenjp2.a $WORK/lib/libwebp.a $WORK/lib/libwebpmux.a $WORK/lib/libwebpdemux.a $WORK/lib/libsharpyuv.a $WORK/lib/libhwy.a $WORK/lib/libbrotlicommon.a $WORK/lib/libbrotlidec.a $WORK/lib/libbrotlienc.a $WORK/lib/libjxl_threads.a $WORK/lib/libjxl_cms.a $WORK/lib/libjxl.a $WORK/lib/libturbojpeg.a $WORK/lib/libjpeg.a $WORK/lib/libfreetype.a $WORK/lib/libraw.a $WORK/lib/liblzma.a $WORK/lib/liblcms2.a $WORK/lib/libdeflate.a $WORK/lib/libz.a"
MAGICK_LIBS="$LIB_FUZZING_ENGINE $MAGICK_LIBS_NO_FUZZ"
MAGICK_OUTPUT=$OUT
MAGICK_FAST_BUILD=0

. $MAGICK_SRC/build_dependencies.sh
. $MAGICK_SRC/build_imagemagick.sh

# Move on the building the fuzzers
MAGICK_COMPILER_FLAGS="$MAGICK_COMPILER_FLAGS -fuse-ld=lld -DMAGICKCORE_HDRI_ENABLE=1 -DMAGICKCORE_QUANTUM_DEPTH=16"

$MAGICK_COMPILER $MAGICK_COMPILER_FLAGS -std=c++11 -I$MAGICK_INCLUDE "$MAGICK_SRC/encoder_list.cc" \
    -o "$MAGICK_SRC/encoder_list" $MAGICK_LIBS_NO_FUZZ


# Control the target fuzzer from the command line. Hardcoded below commented
# out is for testing purposes, and to illustrate the logic behind it.
# TARGET_FUZZER="encoder_sgi_fuzzer"
TARGET_FUZZER=$1

for f in $MAGICK_SRC/*_fuzzer.cc; do
    fuzzer=$(basename "$f" _fuzzer.cc)
    out_fuzzname=$(basename "$f" .cc)
    echo "Real fuzz name: ${out_fuzzname}"
    # encoder_fuzzer is special
    if [ "$fuzzer" == "encoder" ]; then
        continue
    fi
    if [ "$out_fuzzname" != "$TARGET_FUZZER" ]; then
        continue
    fi
    $MAGICK_COMPILER $MAGICK_COMPILER_FLAGS -std=c++11 -I$MAGICK_INCLUDE \
        "$f" -o "$MAGICK_OUTPUT/${fuzzer}_fuzzer" $MAGICK_LIBS &
    echo -e "[libfuzzer]\nclose_fd_mask=3" > "$MAGICK_OUTPUT/${fuzzer}_fuzzer.options"
done

for item in $("$MAGICK_SRC/encoder_list"); do
    info=${item:1}
    encoder=${info%:*}
    initializer=${info##*:}
    encoder_flags="-DFUZZ_IMAGEMAGICK_ENCODER=$encoder"
    out_fuzzname="encoder_${encoder,,}_fuzzer"
    if [ "$out_fuzzname" != "$TARGET_FUZZER" ]; then
        continue
    fi

    if [ "$initializer" != "" ]; then
      encoder_flags="$encoder_flags -DFUZZ_IMAGEMAGICK_ENCODER_INITIALIZER=$initializer"
    fi

    if [ "${item:0:1}" == "+" ]; then
        encoder_flags="$encoder_flags -DFUZZ_IMAGEMAGICK_ENCODER_WRITE=1"
    fi

    $MAGICK_COMPILER $MAGICK_COMPILER_FLAGS -std=c++11 -I$MAGICK_INCLUDE \
        "$MAGICK_SRC/encoder_fuzzer.cc" -o "$MAGICK_OUTPUT/encoder_${encoder,,}_fuzzer" \
         $encoder_flags $MAGICK_LIBS &

    echo -e "[libfuzzer]\nclose_fd_mask=3" > "$MAGICK_OUTPUT/encoder_${encoder,,}_fuzzer.options"

    if [ -f "$MAGICK_SRC/dictionaries/${encoder,,}.dict" ]; then
        cp "$MAGICK_SRC/dictionaries/${encoder,,}.dict" "$MAGICK_OUTPUT/encoder_${encoder,,}_fuzzer.dict"
    fi

    if [ $MAGICK_FAST_BUILD -eq 1 ]; then
        break
    fi
done

wait

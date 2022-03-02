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

set -x

cd $SRC/leptonica
./autogen.sh
./configure --disable-shared
make SUBDIRS=src install -j$(nproc)
ldconfig

cd $SRC/tesseract
./autogen.sh
CXXFLAGS="$CXXFLAGS -D_GLIBCXX_DEBUG" ./configure --disable-graphics --disable-shared
make -j$(nproc)

cp -R $SRC/tessdata $OUT

#LEPTONICA_LIBS=$(pkg-config --static --libs lept)
#LEPTONICA_LIBS="-Wl,-static $LEPTONICA_LIBS"
#LIBS="-Wl,--start-group /src/tesseract/.libs/libtesseract.a -l:libz.a -l:liblept.a -l:libzstd.a -l:libpng16.a -l:libjpeg.a -l:libtiff.a -l:libz.a -l:liblzma.a -Wl,--end-group"
LIBS="-Wl,--start-group /src/tesseract/.libs/libtesseract.a -l:libz.a -l:liblept.a -l:libzstd.a -l:libpng16.a -l:libjpeg.a -l:libtiff.a -l:libz.a -l:liblzma.a -l:libjbig.a -l:libwebp.a -Wl,--end-group"
$CXX $CXXFLAGS \
    -I $SRC/tesseract/include \
    -I/usr/local/include/leptonica \
     $SRC/tesseract/unittest/fuzzers/fuzzer-api.cpp -o $OUT/fuzzer-api \
     $LIB_FUZZING_ENGINE \
     $LIBS

$CXX $CXXFLAGS \
    -DTESSERACT_FUZZER_WIDTH=512 \
    -DTESSERACT_FUZZER_HEIGHT=256 \
    -I $SRC/tesseract/include \
    -I/usr/local/include/leptonica \
     $SRC/tesseract/unittest/fuzzers/fuzzer-api.cpp -o $OUT/fuzzer-api-512x256 \
     $LIB_FUZZING_ENGINE \
     $LIBS

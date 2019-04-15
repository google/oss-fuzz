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

pushd $SRC/freetype2
./autogen.sh
./configure --prefix="$WORK" --disable-shared PKG_CONFIG_PATH="$WORK/lib/pkgconfig"
make -j$(nproc)
make install

mkdir -p $WORK/poppler
pushd $WORK/poppler
cmake $SRC/poppler \
  -DCMAKE_BUILD_TYPE=debug \
  -DBUILD_SHARED_LIBS=OFF \
  -DFONT_CONFIGURATION=generic \
  -DENABLE_DCTDECODER=none \
  -DENABLE_LIBOPENJPEG=none \
  -DENABLE_CMS=none \
  -DENABLE_LIBPNG=OFF \
  -DENABLE_ZLIB=OFF \
  -DENABLE_LIBTIFF=OFF \
  -DENABLE_LIBJPEG=OFF \
  -DENABLE_GLIB=OFF \
  -DENABLE_LIBCURL=OFF \
  -DENABLE_QT5=OFF \
  -DENABLE_UTILS=OFF \
  -DWITH_Cairo=OFF \
  -DWITH_NSS3=OFF \
  -DFREETYPE_INCLUDE_DIRS=$WORK/include/freetype2 \
  -DFREETYPE_LIBRARY=$WORK/lib
make -j$(nproc) poppler poppler-cpp

fuzz_target=pdf_fuzzer

$CXX $CXXFLAGS -std=c++11 -I$SRC/poppler/cpp \
    $SRC/fuzz/pdf_fuzzer.cc -o $OUT/$fuzz_target \
    $LIB_FUZZING_ENGINE $WORK/poppler/cpp/libpoppler-cpp.a $WORK/poppler/libpoppler.a $WORK/lib/libfreetype.a

mv $SRC/{*.zip,*.dict} $OUT

if [ ! -f "${OUT}/${fuzz_target}_seed_corpus.zip" ]; then
  echo "missing seed corpus"
  exit 1
fi

if [ ! -f "${OUT}/${fuzz_target}.dict" ]; then
  echo "missing dictionary"
  exit 1
fi

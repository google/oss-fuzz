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

pushd "$SRC/freetype2"
./autogen.sh
./configure --prefix="$WORK" --disable-shared PKG_CONFIG_PATH="$WORK/lib/pkgconfig"
make -j$(nproc)
make install
popd

pushd poppler

sed "s/poppler SHARED/poppler/" CMakeLists.txt
sed '/option/ a option(BUILD_SHARED_LIBS "Build the shared library" ON)' CMakeLists.txt

mkdir -p $WORK/poppler
pushd $WORK/poppler
cmake $SRC/poppler -DCMAKE_BUILD_TYPE=debug -DENABLE_DCTDECODER=none -DENABLE_LIBOPENJPEG=none -DBUILD_SHARED_LIBS=OFF -DENABLE_LIBPNG=OFF -DFONT_CONFIGURATION=generic -DFREETYPE_INCLUDE_DIRS=$WORK/include/freetype2 -DFREETYPE_LIBRARY=$WORK/lib
make -j$(nproc) poppler poppler-cpp
popd

fuzz_target=pdf_fuzzer

$CXX $CXXFLAGS -std=c++11 -Icpp \
    fuzz/pdf_fuzzer.cc -o $OUT/$fuzz_target \
    -lFuzzingEngine $WORK/poppler/cpp/libpoppler-cpp.a $WORK/poppler/libpoppler.a $WORK/lib/libfreetype.a

mv $SRC/{*.zip,*.dict,*.options} $OUT

if [ ! -f "${OUT}/${fuzz_target}_seed_corpus.zip" ]; then
  echo "missing seed corpus"
  exit 1
fi

if [ ! -f "${OUT}/${fuzz_target}.dict" ]; then
  echo "missing dictionary"
  exit 1
fi

if [ ! -f "${OUT}/${fuzz_target}.options" ]; then
  echo "missing options"
  exit 1
fi

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

# static lcms2 not available in Ubuntu
cd $SRC/lcms2
./configure --disable-shared CFLAGS=
make clean
make -j$(nproc)
cd $SRC/poppler-build

### cpp API
cmake $SRC/poppler \
  -DBUILD_CPP_TESTS=OFF \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=$CC \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_C_FLAGS_RELEASE=-DNDEBUG \
  -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_CXX_FLAGS_RELEASE=-DNDEBUG \
  -DENABLE_GLIB=OFF \
  -DENABLE_LIBCURL=OFF \
  -DENABLE_QT5=OFF \
  -DENABLE_UTILS=OFF \
  -DENABLE_LIBOPENJPEG=none \
  -DENABLE_CMS=lcms2 \
  -DLCMS2_INCLUDE_DIR=$SRC/lcms2/include \
  -DLCMS2_LIBRARIES=$SRC/lcms2/src/.libs/liblcms2.a \
  -DPOPPLER_DATADIR=$SRC/poppler-data \
  -DWITH_Cairo=OFF \
  -DWITH_NSS3=OFF

make clean
make -j$(nproc)

$CXX $CXXFLAGS -std=c++11 \
  -I$SRC/poppler \
  $SRC/fuzz_cpp.cc -o $OUT/fuzz_cpp \
  cpp/libpoppler-cpp.a libpoppler.a \
  -lFuzzingEngine \
  $SRC/lcms2/src/.libs/liblcms2.a \
  -nodefaultlibs -lc++ -lc -ldl -lgcc_s -lgcc -lm -lrt \
  -lpthread \
  -Wl,-Bstatic \
  -lfontconfig -lexpat -lfreetype -ljpeg -lpng -ltiff -ljbig -llzma -lz
  
cp $SRC/fuzz_cpp.dict $OUT
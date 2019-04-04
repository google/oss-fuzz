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

# libjpeg-turbo
pushd $SRC/libjpeg-turbo
cmake . -DCMAKE_INSTALL_PREFIX="$WORK" -DENABLE_STATIC:bool=on
make -j$(nproc)
make install
popd

# qpdf
./configure \
  --enable-static \
  --disable-shared \
  --prefix="$WORK" \
  LDFLAGS="-L$WORK/lib" \
  CPPFLAGS="-I$WORK/include" \
  LIBS="-pthread"
make -j$(nproc)
make install

$CXX $CXXFLAGS -std=c++11 -I"$WORK/include" \
  "$SRC/qpdf_read_memory_fuzzer.cc" -o "$OUT/qpdf_read_memory_fuzzer" \
  "$WORK/lib/libqpdf.a" \
  "$WORK/lib/libjpeg.a" \
  "$WORK/lib/libz.a" \
  -pthread \
  $LIB_FUZZING_ENGINE

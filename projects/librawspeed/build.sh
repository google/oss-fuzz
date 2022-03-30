#!/bin/bash -eu
# Copyright 2017 Google Inc.
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

set -e

if [[ $SANITIZER = *undefined* ]]; then
  CFLAGS="$CFLAGS -fsanitize=unsigned-integer-overflow -fno-sanitize-recover=unsigned-integer-overflow"
  CXXFLAGS="$CXXFLAGS -fsanitize=unsigned-integer-overflow -fno-sanitize-recover=unsigned-integer-overflow"
fi

cd "$WORK"
mkdir build
cd build

# Temporarily use gold for linking because of BFD breakage (see
# https://github.com/google/oss-fuzz/pull/2781).
ln -f -s /usr/bin/gold /usr/bin/ld
cmake \
  -G"Unix Makefiles" -DBINARY_PACKAGE_BUILD=ON -DWITH_OPENMP=OFF \
  -DWITH_PUGIXML=OFF -DUSE_XMLLINT=OFF -DWITH_JPEG=OFF -DWITH_ZLIB=OFF \
  -DBUILD_TESTING=OFF -DBUILD_TOOLS=OFF -DBUILD_BENCHMARKING=OFF \
  -DCMAKE_BUILD_TYPE=FUZZ -DBUILD_FUZZERS=ON \
  -DLIB_FUZZING_ENGINE:STRING="$LIB_FUZZING_ENGINE" \
  -DCMAKE_INSTALL_PREFIX:PATH="$OUT" -DCMAKE_INSTALL_BINDIR:PATH="$OUT" \
  "$SRC/librawspeed/"

make -j$(nproc) all && make -j$(nproc) install

cd "$SRC"
rm -rf "$WORK/build"

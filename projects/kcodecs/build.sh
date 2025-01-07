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

cd $SRC
tar xzf gperf*.tar.gz && rm -f gperf*.tar.gz
cd gperf*
FUZZ_CFLAGS="${CFLAGS}"
FUZZ_CXXFLAGS="${CXXFLAGS}"
unset CFLAGS
unset CXXFLAGS
# gperf is a code generator, so no need to sanitize it
./configure --prefix=/usr CXX='clang++ -std=c++14'  # Avoid C++17 due to clang-18 error
make -j$(nproc) install
export CFLAGS="${FUZZ_CFLAGS}"
export CXXFLAGS="${FUZZ_CXXFLAGS}"


cd $SRC
cd extra-cmake-modules
cmake -DBUILD_TESTING=OFF .
make install

cd $SRC
cd qtbase
./configure -no-glib -qt-libpng -qt-pcre -qt-zlib -opensource -confirm-license -static -no-opengl -no-icu -platform linux-clang-libc++ -debug -prefix /usr -no-feature-gui -no-feature-sql -no-feature-network  -no-feature-xml -no-feature-dbus -no-feature-printsupport
cmake --build . --parallel $(nproc)
cmake --install .

cd $SRC
cd kcodecs
rm -rf poqm
cmake . -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc) VERBOSE=1

$CXX $CXXFLAGS -fPIC -std=c++17 $SRC/kcodecs_fuzzer.cc -o $OUT/kcodecs_fuzzer \
               -I /usr/include/QtCore/ -I $SRC/kcodecs/src \
               -I $SRC/kcodecs/src/probers -L $SRC/kcodecs/lib \
               -lQt6Core -lm -lQt6BundledPcre2 -lQt6BundledZLIB -ldl -lpthread $LIB_FUZZING_ENGINE -lKF6Codecs

zip -qr $OUT/kcodecs_fuzzer_seed_corpus.zip $SRC/uchardet/test/ $SRC/kcodecs/autotests/data

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

if [[ $CFLAGS = *sanitize=address* ]]
then
    export CXXFLAGS="$CXXFLAGS -DASAN"
fi

if [[ $CFLAGS = *sanitize=memory* ]]
then
    export CXXFLAGS="$CXXFLAGS -DMSAN"
fi

mkdir $SRC/libogg-install/
cd $SRC/ogg
./autogen.sh
./configure --prefix="$SRC/libogg-install" --enable-static --disable-shared --disable-crc
make -j$(nproc)
make install

cd $SRC/fuzzing-headers/
./install.sh

cd $SRC/libtheora/
./autogen.sh

if [[ $CFLAGS = *sanitize=memory* || $CFLAGS = *-m32* ]]
then
    LD_LIBRARY_PATH="$SRC/libogg-install/lib" ./configure --with-ogg="$SRC/libogg-install" --disable-encode --disable-examples --disable-asm --enable-static --disable-shared
else
    LD_LIBRARY_PATH="$SRC/libogg-install/lib" ./configure --with-ogg="$SRC/libogg-install" --disable-encode --disable-examples --enable-static --disable-shared
fi

make -j$(nproc)

cd $SRC/oss-fuzz-fuzzers/libtheora/

$CXX $CXXFLAGS -I $SRC/libtheora/include/ -I $SRC/libogg-install/include fuzzer.cpp $SRC/libtheora/lib/.libs/libtheora.a $LIB_FUZZING_ENGINE -o $OUT/fuzzer-decoder

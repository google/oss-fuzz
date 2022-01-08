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

# Build dependencies.
export DEPS_PATH=$SRC/deps
mkdir -p $DEPS_PATH

cd $SRC/x265/build/linux
cmake -G "Unix Makefiles" \
    -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
    -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DCMAKE_INSTALL_PREFIX="$DEPS_PATH" \
    -DENABLE_SHARED:bool=off \
    ../../source
make clean
make -j$(nproc) x265-static
make install

cd $SRC/libde265
./autogen.sh
./configure \
    --prefix="$DEPS_PATH" \
    --disable-shared \
    --enable-static \
    --disable-dec265 \
    --disable-sherlock265 \
    --disable-hdrcopy \
    --disable-enc265 \
    --disable-acceleration_speed
make clean
make -j$(nproc)
make install

mkdir -p $SRC/aom/build/linux
cd $SRC/aom/build/linux
cmake -G "Unix Makefiles" \
  -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX \
  -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_INSTALL_PREFIX="$DEPS_PATH" \
  -DENABLE_SHARED:bool=off -DCONFIG_PIC=1 \
  -DENABLE_EXAMPLES=0 -DENABLE_DOCS=0 -DENABLE_TESTS=0 \
  -DCONFIG_SIZE_LIMIT=1 \
  -DDECODE_HEIGHT_LIMIT=12288 -DDECODE_WIDTH_LIMIT=12288 \
  -DDO_RANGE_CHECK_CLAMP=1 \
  -DAOM_MAX_ALLOCABLE_MEMORY=536870912 \
  -DAOM_TARGET_CPU=generic \
  ../../
make clean
make -j$(nproc)
make install

# Remove shared libraries to avoid accidental linking against them.
rm -f $DEPS_PATH/lib/*.so
rm -f $DEPS_PATH/lib/*.so.*

cd $SRC/libheif
./autogen.sh
PKG_CONFIG="pkg-config --static" PKG_CONFIG_PATH="$DEPS_PATH/lib/pkgconfig" ./configure \
    --disable-shared \
    --enable-static \
    --disable-examples \
    --disable-go \
    --enable-libfuzzer="$LIB_FUZZING_ENGINE" \
    CPPFLAGS="-I$DEPS_PATH/include"
make clean
make -j$(nproc)

cp libheif/*-fuzzer $OUT
cp fuzzing/dictionary.txt $OUT/box-fuzzer.dict
cp fuzzing/dictionary.txt $OUT/file-fuzzer.dict

zip -r $OUT/file-fuzzer_seed_corpus.zip fuzzing/corpus/*.heic

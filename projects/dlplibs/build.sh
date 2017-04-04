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

# HACK to link with static icu
mkdir icu
cp -p /usr/lib/*/libicu*.a icu
iculib=$(pwd)/icu

pushd librevenge
./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tests --enable-fuzzers
make -j$(nproc)
rvnginc=$(pwd)/inc
rvnglib=$(pwd)/src/lib
popd

pushd libmspub
./autogen.sh
./configure --without-docs --disable-shared --enable-static --disable-tools --enable-fuzzers \
    ICU_CFLAGS="$(pkg-config --cflags icu-i18n)" \
    ICU_LIBS="-L$iculib $(pkg-config --libs icu-i18n)" \
    REVENGE_CFLAGS=-I$rvnginc REVENGE_LIBS="-L$rvnglib -lrevenge-0.0" \
    REVENGE_STREAM_CFLAGS=-I$rvnginc REVENGE_STREAM_LIBS="-L$rvnglib -lrevenge-stream-0.0" \
    REVENGE_GENERATORS_CFLAGS=-I$rvnginc REVENGE_GENERATORS_LIBS="-L$rvnglib -lrevenge-generators-0.0"
make -j$(nproc)
popd

cp */src/fuzz/*fuzzer $OUT
cp *_seed_corpus.zip $OUT

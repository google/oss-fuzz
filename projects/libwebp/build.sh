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

# limit allocation size to reduce spurious OOMs
WEBP_CFLAGS="$CFLAGS -DWEBP_MAX_IMAGE_SIZE=838860800" # 800MiB

./autogen.sh
CFLAGS="$WEBP_CFLAGS" ./configure \
  --enable-libwebpdemux \
  --disable-shared \
  --disable-jpeg \
  --disable-tiff \
  --disable-gif \
  --disable-wic
make clean
make -j$(nproc)

cp $SRC/fuzz.dict $OUT

# Simple Decoding API
$CC $CFLAGS -Isrc -c $SRC/fuzz_simple_api.c
$CXX $CXXFLAGS -lFuzzingEngine \
  fuzz_simple_api.o -o $OUT/fuzz_simple_api \
  src/.libs/libwebp.a
cp $SRC/fuzz_seed_corpus.zip $OUT/fuzz_simple_api_seed_corpus.zip
cp $SRC/fuzz_simple_api.options $OUT

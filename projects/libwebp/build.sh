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
  --enable-asserts \
  --enable-libwebpdemux \
  --enable-libwebpmux \
  --disable-shared \
  --disable-jpeg \
  --disable-tiff \
  --disable-gif \
  --disable-wic
make clean
make -j$(nproc)

find $SRC/libwebp-test-data -type f -size -32k -iname "*.webp" \
  -exec zip -qju fuzz_seed_corpus.zip "{}" \;

# Simple Decoding API
$CC $CFLAGS -Isrc -I. -c $SRC/fuzz_simple_api.c
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
  fuzz_simple_api.o -o $OUT/fuzz_simple_api \
  src/.libs/libwebp.a
cp fuzz_seed_corpus.zip $OUT/fuzz_simple_api_seed_corpus.zip
cp $SRC/fuzz.dict $OUT/fuzz_simple_api.dict

# Advanced Decoding API
$CC $CFLAGS -Isrc -I. -c $SRC/fuzz_advanced_api.c
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
  fuzz_advanced_api.o -o $OUT/fuzz_advanced_api \
  src/.libs/libwebp.a
cp fuzz_seed_corpus.zip $OUT/fuzz_advanced_api_seed_corpus.zip
cp $SRC/fuzz.dict $OUT/fuzz_advanced_api.dict

# Animation Decoding API
$CC $CFLAGS -Isrc -I. -c $SRC/fuzz_animation_api.c
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
  fuzz_animation_api.o -o $OUT/fuzz_animation_api \
  src/demux/.libs/libwebpdemux.a \
  src/.libs/libwebp.a
cp fuzz_seed_corpus.zip $OUT/fuzz_animation_api_seed_corpus.zip
cp $SRC/fuzz.dict $OUT/fuzz_animation_api.dict

# Animation Encoding API
$CC $CFLAGS -Isrc -I. -c $SRC/fuzz_webp_animencoder.cc
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
  fuzz_webp_animencoder.o -o $OUT/fuzz_webp_animencoder \
  src/mux/.libs/libwebpmux.a \
  src/.libs/libwebp.a
cp fuzz_seed_corpus.zip $OUT/fuzz_webp_animencoder_seed_corpus.zip

# (De)mux API
$CC $CFLAGS -Isrc -I. -c $SRC/fuzz_demux_api.c
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
  fuzz_demux_api.o -o $OUT/fuzz_demux_api \
  src/demux/.libs/libwebpdemux.a src/mux/.libs/libwebpmux.a \
  src/.libs/libwebp.a
cp fuzz_seed_corpus.zip $OUT/fuzz_demux_api_seed_corpus.zip
cp $SRC/fuzz.dict $OUT/fuzz_demux_api.dict

# Encode then Decode
$CC $CFLAGS -Isrc -I. -c $SRC/fuzz_webp_enc_dec.cc
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
  fuzz_webp_enc_dec.o -o $OUT/fuzz_webp_enc_dec \
  src/.libs/libwebp.a
cp fuzz_seed_corpus.zip $OUT/fuzz_webp_enc_dec_seed_corpus.zip

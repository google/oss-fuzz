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

webp_libs=(
  src/demux/.libs/libwebpdemux.a
  src/mux/.libs/libwebpmux.a
  src/.libs/libwebp.a
  imageio/.libs/libimageio_util.a
  sharpyuv/.libs/libsharpyuv.a
)
webp_c_fuzzers=(
  advanced_api_fuzzer
  animation_api_fuzzer
  mux_demux_api_fuzzer
  simple_api_fuzzer
)
webp_cxx_fuzzers=(
  animdecoder_fuzzer
  animencoder_fuzzer
  enc_dec_fuzzer
)

for fuzzer in "${webp_c_fuzzers[@]}"; do
  $CC $CFLAGS -Isrc -I. tests/fuzzer/${fuzzer}.c -c -o tests/fuzzer/${fuzzer}.o
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
    tests/fuzzer/${fuzzer}.o -o $OUT/${fuzzer} \
    "${webp_libs[@]}"
done

for fuzzer in "${webp_cxx_fuzzers[@]}"; do
  $CXX $CXXFLAGS -Isrc -I. $LIB_FUZZING_ENGINE \
    tests/fuzzer/${fuzzer}.cc -o $OUT/${fuzzer} \
    "${webp_libs[@]}"
done

for fuzzer in "${webp_c_fuzzers[@]}" "${webp_cxx_fuzzers[@]}"; do
  cp fuzz_seed_corpus.zip $OUT/${fuzzer}_seed_corpus.zip
  cp tests/fuzzer/fuzz.dict $OUT/${fuzzer}.dict
done

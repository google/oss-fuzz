#!/bin/bash -eu
# Copyright 2026 Google Inc.
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

# Build libwebp (static: libwebp, libwebpdemux, libwebpmux, sharpyuv)
cmake . \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_SHARED=0 \
  -DENABLE_STATIC=1 \
  -DWEBP_BUILD_CWEBP=0 \
  -DWEBP_BUILD_DWEBP=0 \
  -DWEBP_BUILD_GIF2WEBP=0 \
  -DWEBP_BUILD_IMG2WEBP=0 \
  -DWEBP_BUILD_VWEBP=0 \
  -DWEBP_BUILD_WEBPMUX=0 \
  -DWEBP_BUILD_WEBP_JS=0 \
  -DWEBP_BUILD_EXTRAS=0 \
  -DWEBP_ENABLE_SIMD=1

make -j$(nproc) webp webpdemux libwebpmux sharpyuv

# Build fuzz targets
# fuzz_webp_mux needs webpmux -> webp order; use --start/end-group for safety
for fuzzer in fuzz_webp_decode fuzz_webp_demux fuzz_webp_mux; do
  $CXX $CXXFLAGS -std=c++11 \
    -I"$SRC/libwebp" \
    "$SRC/${fuzzer}.cc" \
    -o "$OUT/${fuzzer}" \
    $LIB_FUZZING_ENGINE \
    -Wl,--start-group \
      libwebpmux.a libwebpdemux.a libwebp.a libsharpyuv.a \
    -Wl,--end-group
done

# Seed corpus: use bundled test images if available
SEED_DIR="$SRC/libwebp/tests/testdata"
if [ -d "$SEED_DIR" ]; then
  zip -j "$OUT/fuzz_webp_decode_seed_corpus.zip" "$SEED_DIR"/*.webp 2>/dev/null || true
  ln -sf "$OUT/fuzz_webp_decode_seed_corpus.zip" "$OUT/fuzz_webp_demux_seed_corpus.zip"
  ln -sf "$OUT/fuzz_webp_decode_seed_corpus.zip" "$OUT/fuzz_webp_mux_seed_corpus.zip"
fi

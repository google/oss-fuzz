#!/bin/bash -eux
# Copyright 2025 Google LLC
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

# Disable UBSan vptr since several targets built with -fno-rtti.
export CFLAGS="$CFLAGS -fno-sanitize=vptr"
export CXXFLAGS="$CXXFLAGS -fno-sanitize=vptr"

if [[ "$CXXFLAGS" == *"-fsanitize=address"* ]]; then
    export CXXFLAGS="$CXXFLAGS -fno-sanitize-address-use-odr-indicator"
fi

if [[ "$CFLAGS" == *"-fsanitize=address"* ]]; then
    export CFLAGS="$CFLAGS -fno-sanitize-address-use-odr-indicator"
fi

if [[ "$ARCHITECTURE" == i386 ]]; then
  export CFLAGS="$CFLAGS -m32"
  export CXXFLAGS="$CXXFLAGS -m32"
fi

# The option `-fuse-ld=gold` can't be passed via `CFLAGS` or `CXXFLAGS` because
# Meson injects `-Werror=ignored-optimization-argument` during compile tests.
# Remove the `-fuse-ld=` and let Meson handle it.
# https://github.com/mesonbuild/meson/issues/6377#issuecomment-575977919
export MESON_CFLAGS="$CFLAGS"
if [[ "$CFLAGS" == *"-fuse-ld=gold"* ]]; then
    export MESON_CFLAGS="${CFLAGS//-fuse-ld=gold/}"
    export CC_LD=gold
fi
export MESON_CXXFLAGS="$CXXFLAGS"
if [[ "$CXXFLAGS" == *"-fuse-ld=gold"* ]]; then
    export MESON_CXXFLAGS="${CXXFLAGS//-fuse-ld=gold/}"
    export CXX_LD=gold
fi

cd $SRC/ffmpeg
make -j$(nproc) install

if [ "$#" -lt 1 ]; then
  exit 0
fi

name=$(echo "$1" | sed -E 's/ffmpeg_(AV_CODEC_ID_)?(.*)_fuzzer/\L\2/' | sed 's/demuxer/dem/')
make tools/target_${name}_fuzzer || true
if [ -f tools/target_${name}_fuzzer ]; then
  mv tools/target_${name}_fuzzer $OUT/$1
fi

make tools/target_dec_${name}_fuzzer || true
if [ -f tools/target_dec_${name}_fuzzer ]; then
  mv tools/target_dec_${name}_fuzzer $OUT/$1
fi

make tools/target_enc_${name}_fuzzer || true
if [ -f tools/target_enc_${name}_fuzzer ]; then
  mv tools/target_enc_${name}_fuzzer $OUT/$1
fi

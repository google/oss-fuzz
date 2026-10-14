#!/bin/bash -eu
# Copyright 2026 Google LLC
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

cd $SRC/libmobi

# Build libmobi as a static library
./autogen.sh
./configure \
  --disable-shared \
  --enable-static \
  --without-minizip \
  CC="$CC" \
  CFLAGS="$CFLAGS"

make -j$(nproc) V=1

# Locate static lib
LIBMOBI_INCLUDE="$SRC/libmobi/src"
LIBMOBI_LIB="$SRC/libmobi/src/.libs/libmobi.a"

# Build each fuzz target
for fuzzer in fuzz_load fuzz_parse_rawml fuzz_huffman; do
  $CC $CFLAGS \
    -I"$LIBMOBI_INCLUDE" \
    "$SRC/${fuzzer}.c" \
    "$LIBMOBI_LIB" \
    -lxml2 \
    -lz \
    $LIB_FUZZING_ENGINE \
    -o "$OUT/${fuzzer}"
done

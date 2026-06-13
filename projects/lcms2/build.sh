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

# Build lcms2 as a static library.
./autogen.sh
./configure --disable-shared --enable-static

make -j$(nproc)

# Build the fuzz target.
$CC $CFLAGS \
  -I"$SRC/lcms2/include" \
  "$SRC/fuzz_icc_profile.c" \
  -o "$OUT/fuzz_icc_profile" \
  $LIB_FUZZING_ENGINE \
  src/.libs/liblcms2.a

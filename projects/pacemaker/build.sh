#!/bin/bash -eu
# Copyright 2024 Google LLC
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

export CFLAGS="$CFLAGS -Wno-deprecated-declarations"
export CXXFLAGS="$CXXFLAGS -Wno-deprecated-declarations"
make -j$(nproc) build

for FUZZER_SOURCE in lib/*/fuzzers/*.c; do
  FUZZER="$(basename "$FUZZER_SOURCE" .c)"

  $CC $CFLAGS $LIB_FUZZING_ENGINE -c "$FUZZER_SOURCE"                      \
   -o "${OUT}/${FUZZER}.o"                                                 \
   -I./include -I/usr/local/include/libxml2 -I/usr/include/glib-2.0        \
   -I/usr/lib/x86_64-linux-gnu/glib-2.0/include/

  # Link with CXX for Centipede
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE                                       \
   "$OUT/${FUZZER}.o" -o "$OUT/${FUZZER}"                                  \
   ./lib/cib/.libs/libcib.a ./lib/pengine/.libs/libpe_rules.a              \
   ./lib/common/.libs/libcrmcommon.a -l:libqb.a                            \
   -l:libxslt.a -l:libxml2.a -l:libglib-2.0.a -l:libuuid.a -l:libicuuc.a   \
   -l:libz.a -lgnutls -lbz2 -lrt -ldl -lc
done

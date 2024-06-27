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
make build -j$(nproc)

for fuzzer in iso8601 cib_file; do
  $CC $CFLAGS $LIB_FUZZING_ENGINE -c ./fuzzers/${fuzzer}_fuzzer.c          \
   -I/usr/local/include/libxml2/ -I./include/crm/common -I./include        \
   -I./include/crm/ -I/usr/include/glib-2.0                                \
   -I/usr/lib/x86_64-linux-gnu/glib-2.0/include/

  # Link with CXX for Centipede
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE ${fuzzer}_fuzzer.o                    \
   -o $OUT/${fuzzer}_fuzzer                                                \
   -Wl,--start-group ./lib/cib/.libs/libcib.a                              \
   ./lib/common/.libs/libcrmcommon.a -lbz2                                 \
   -l:libxslt.a -lrt -ldl -lc -l:libuuid.a -l:libicuuc.a -l:libglib-2.0.a  \
   -l:libz.a -l:libxml2.a ./lib/cib/.libs/libcib.a                         \
   ./lib/pengine/.libs/libpe_rules.a ./lib/pengine/.libs/libpe_status.a    \
   -lgnutls \
   -Wl,--end-group -l:libqb.a
done

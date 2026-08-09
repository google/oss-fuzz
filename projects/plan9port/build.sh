#!/bin/bash -eu
# Copyright 2023 Google LLC
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

# Apply fuzzing patches
git apply  --ignore-space-change --ignore-whitespace $SRC/fuzz_patch.diff

export CC9=$CC
export CC9FLAGS="$CFLAGS"
export ASAN_OPTIONS="detect_leaks=0"
./INSTALL

plan9_libs="-Wl,--start-group ./lib/libframe.a ./lib/libbio.a ./lib/libdisk.a ./lib/lib9.a ./lib/libcomplete.a ./lib/libString.a ./lib/libauth.a ./lib/libmemlayer.a ./lib/libventi.a ./lib/libmux.a ./lib/lib9p.a ./lib/libregexp9.a ./lib/libip.a ./lib/libgeometry.a ./lib/libhtml.a ./lib/libmp.a ./lib/libplumb.a ./lib/libsec.a ./lib/libflate.a ./lib/libhttpd.a ./lib/libndb.a ./lib/libdraw.a ./lib/libmach.a ./lib/libavl.a ./lib/libthread.a ./lib/libauthsrv.a ./lib/libdiskfs.a ./lib/lib9pclient.a ./lib/libsunrpc.a ./lib/libmemdraw.a ./lib/libacme.a ./lib/libbin.a -Wl,--end-group"

$CC $CFLAGS $LIB_FUZZING_ENGINE -c $SRC/fuzz_libsec.c \
    -o fuzz_libsec.o -I./include
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_libsec.o \
    -o $OUT/fuzz_libsec -I./include $plan9_libs

cp $SRC/fuzz_libsec.options $OUT/fuzz_libsec.options

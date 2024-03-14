#!/bin/bash -eu
# Copyright 2021 Google LLC
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

git apply $SRC/busybox_patch.txt

sed -i 's/gcc/clang/g' ./Makefile
make defconfig
make V=1

# We need to remove old main
cd libbb
rm lib.a
rm appletlib.o

ar cr lib.a *.o
cd ../


for fuzz in libbb archival; do
  $CC $CFLAGS -std=gnu99 -Iinclude -Ilibbb  -include include/autoconf.h \
    -D_GNU_SOURCE -DNDEBUG -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 \
    -DBB_VER='"1.34.0.git"' $LIB_FUZZING_ENGINE \
    $SRC/fuzz_${fuzz}.c ./libbb/lib.a ./archival/libarchive/lib.a ./archival/lib.a \
    coreutils/lib.a ./libbb/lib.a -I./include/ -o $OUT/fuzz_${fuzz}
done

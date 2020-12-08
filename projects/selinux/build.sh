#!/bin/bash -e
# Copyright 2020 Google Inc.
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

export DESTDIR=$(pwd)/DESTDIR
export LDFLAGS="${LDFLAGS:-} $CFLAGS"

find -name Makefile | xargs sed -i 's/,-z,defs//'
make V=1 -j$(nproc) install

$CC $CFLAGS -I$DESTDIR/usr/include -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -c -o secilc-fuzzer.o $SRC/secilc-fuzzer.c
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE secilc-fuzzer.o $DESTDIR/usr/lib/libsepol.a -o $OUT/secilc-fuzzer
zip -r $OUT/secilc-fuzzer_seed_corpus.zip secilc/test

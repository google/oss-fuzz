#!/bin/bash -eu
# Copyright 2022 Google LLC
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
./autogen.sh
./configure CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="$CFLAGS" --disable-shared --disable-hardening --enable-pie
make

$CC $CFLAGS -fPIE -Wall -Werror -pipe -DHAVE_CONFIG_H -I. -I include/ -c FuzzDecode.c
$CXX $CXXFLAGS -fPIE -pie -o FuzzDecode FuzzDecode.o $LIB_FUZZING_ENGINE src/daemon/.libs/liblldpd.a libevent/.libs/libevent.a
cp FuzzDecode $OUT/FuzzDecode

pushd $SRC/oss-fuzz-bloat/lldpd/
cp FuzzDecode_seed_corpus.zip $OUT/FuzzDecode_seed_corpus.zip
popd

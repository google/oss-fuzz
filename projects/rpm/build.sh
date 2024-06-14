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

export LDFLAGS="-llua5.2"
./autogen.sh --noconfigure 
sed -i 's/lua\ /lua5.2\ /g' ./configure
./configure --disable-sqlite --enable-static
make

$CC $CFLAGS $LIB_FUZZING_ENGINE $SRC/fuzz_header.c -o $OUT/fuzz_header \
  -DHAVE___PROGNAME ./lib/.libs/librpm.a ./rpmio/.libs/librpmio.a -I./include/ -I./ \
  -Wl,--start-group -l:liblua5.2.a -l:libgcrypt.a -l:libgpg-error.a -l:libpopt.a -Wl,--end-group -lz

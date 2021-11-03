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

./bootstrap
autoreconf -f
./configure
make

DEP_INCLUDES="-I. -I/usr/include/dbus-1.0 -I/usr/lib/x86_64-linux-gnu/dbus-1.0/include -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -I./lib -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -I/usr/include/dbus-1.0 -I/usr/lib/x86_64-linux-gnu/dbus-1.0/include  -I./lib -I./obexd/src"

STATIC_LIBS="./src/.libs/libshared-glib.a ./lib/.libs/libbluetooth-internal.a  -l:libical.a -l:libicalss.a -l:libicalvcal.a -l:libdbus-1.a -l:libglib-2.0.a"
$CC $CFLAGS $LIB_FUZZING_ENGINE $DEP_INCLUDES \
 $SRC/fuzz_sdp.c -o $OUT/fuzz_sdp \
 $STATIC_LIBS -ldl -lpthread


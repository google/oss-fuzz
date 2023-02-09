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

INCLUDES="-I. -I./src -I./lib -I./gobex -I/usr/local/include/glib-2.0/ -I/src/glib/_build/glib/"
STATIC_LIBS="./src/.libs/libshared-glib.a ./lib/.libs/libbluetooth-internal.a  -l:libical.a -l:libicalss.a -l:libicalvcal.a -l:libdbus-1.a /src/glib/_build/glib/libglib-2.0.a"

$CC $CFLAGS $INCLUDES $SRC/fuzz_xml.c -c
$CC $CFLAGS $INCLUDES $SRC/fuzz_sdp.c -c
$CC $CFLAGS $INCLUDES $SRC/fuzz_textfile.c -c
$CC $CFLAGS $INCLUDES $SRC/fuzz_gobex.c -c
$CC $CFLAGS $INCLUDES $SRC/fuzz_hci.c -c

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
 ./src/bluetoothd-sdp-xml.o fuzz_xml.o -o $OUT/fuzz_xml \
 $STATIC_LIBS -ldl -lpthread

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
 fuzz_sdp.o -o $OUT/fuzz_sdp $STATIC_LIBS -ldl -lpthread

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE fuzz_textfile.o -o $OUT/fuzz_textfile \
  $STATIC_LIBS -ldl -lpthread src/textfile.o

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
  fuzz_gobex.o ./gobex/gobex*.o -o $OUT/fuzz_gobex \
 $STATIC_LIBS -ldl -lpthread

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
 fuzz_hci.o ./gobex/gobex*.o -o $OUT/fuzz_hci \
 $STATIC_LIBS -ldl -lpthread

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

DIR=$SRC/libwebsockets/

cd $DIR
mkdir build && cd build

cmake -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      -DCMAKE_EXE_LINKER_FLAGS="$CFLAGS" -DCMAKE_SHARED_LINKER_FLAGS="$CFLAGS" ..
make -j8

cd $DIR
$CXX $CFLAGS $LIB_FUZZING_ENGINE -I$DIR/build/include \
	-o $OUT/lws_upng_inflate_fuzzer lws_upng_inflate_fuzzer.cpp \
	-L$DIR/build/lib -l:libwebsockets.a \
	-L/usr/lib/x86_64-linux-gnu/ -l:libssl.so -l:libcrypto.so

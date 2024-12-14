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
sed -i 's/-Werror//g' ./CMakeLists.txt
mkdir build && cd build
cmake -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
      -DCMAKE_EXE_LINKER_FLAGS="$CFLAGS" -DCMAKE_SHARED_LINKER_FLAGS="$CFLAGS" \
      -DLWS_WITH_CUSTOM_HEADERS=ON \
      -DLWS_ROLE_WS=ON \
      ..
make -j8

cd $DIR

INCLUDE_DIRS="-I$DIR/build/include \
	-I$DIR/build \
	-I$DIR/lib/core/ \
	-I$DIR/lib/plat/unix -I$DIR/lib/tls/ \
	-I$DIR/lib/secure-streams/ \
	-I$DIR/lib/event-libs/ \
	-I$DIR/lib/system/smd \
	-I$DIR/lib/system/metrics/ \
	-I$DIR/lib/core-net \
	-I$DIR/lib/roles \
	-I$DIR/lib/roles/http \
	-I$DIR/lib/roles/h1 \
	-I$DIR/lib/roles/h2 \
	-I$DIR/lib/roles/ws"

FUZZER_SRCS=(
    "lws_lhs_fuzzer.cpp"
    "lws_upng_inflate_fuzzer.cpp"
    "lws_parse_uri_fuzzer.cpp"
    "lws_parse_fuzzer.cpp"
)

for FUZZER in "${FUZZER_SRCS[@]}"; do
    FUZZER_NAME=$(basename "$FUZZER" .cpp)
    $CXX $CFLAGS $LIB_FUZZING_ENGINE $INCLUDE_DIRS \
        -o "$OUT/$FUZZER_NAME" $FUZZER \
        -L"$DIR/build/lib" -l:libwebsockets.a \
        -L/usr/lib/x86_64-linux-gnu/ -l:libssl.so -l:libcrypto.so
done

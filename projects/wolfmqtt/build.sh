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

# Build wolfSSL (dependency of wolfMQTT)
cd $SRC/wolfssl/
autoreconf -ivf
if [[ $CFLAGS = *sanitize=memory* ]]
then
    ./configure --enable-static --disable-crypttests --disable-examples --disable-asm
elif [[ $CFLAGS = *-m32* ]]
then
    ./configure --enable-static --disable-crypttests --disable-examples --disable-fastmath
else
    ./configure --enable-static --disable-crypttests --disable-examples
fi
make -j$(nproc)
export CFLAGS="$CFLAGS -I $(realpath .)"
export LDFLAGS="-L$(realpath src/.libs/)"

# Build wolfMQTT
cd $SRC/wolfmqtt/
./autogen.sh
./configure --enable-static --disable-examples --enable-mqtt5
make -j$(nproc)

$CXX $CXXFLAGS \
    -std=c++17 \
    -I $SRC/fuzzing-headers/include/ \
    -I $SRC/wolfssl/ \
    -I $SRC/wolfmqtt/ \
    $SRC/wolfmqtt-fuzzers/fuzzer.cpp \
    $SRC/wolfmqtt/src/.libs/libwolfmqtt.a \
    $SRC/wolfssl/src/.libs/libwolfssl.a \
    $LIB_FUZZING_ENGINE \
    -o $OUT/wolfmqtt-fuzzer
